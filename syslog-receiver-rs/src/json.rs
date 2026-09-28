//! JSON/time formatting. Field order and shapes match the Go receiver's `logEvent`.

use crate::parse::{facility_name, severity_name, Entry};
use std::time::{SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 -> (year, month, day), proleptic Gregorian (Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn parts(t: SystemTime) -> (i64, u32, u32, u32, u32, u32, u32) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (y, mo, da) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400) as u32;
    (y, mo, da, sod / 3600, sod % 3600 / 60, sod % 60, d.subsec_nanos())
}

/// Same output as Go's `time.RFC3339Nano` in UTC (trailing zeros trimmed).
pub fn rfc3339_nano(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s, ns) = parts(t);
    let mut out = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}");
    if ns != 0 {
        let frac = format!("{ns:09}");
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }
    out.push('Z');
    out
}

/// Millisecond precision ISO string for ClickHouse `DateTime64(3)` (best_effort input).
pub fn rfc3339_millis(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s, ns) = parts(t);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}Z", ns / 1_000_000)
}

/// Escape like Go's encoding/json (HTML-safe by default).
pub fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn field(out: &mut String, name: &str, val: &str) {
    out.push('"');
    out.push_str(name);
    out.push_str("\":");
    push_str(out, val);
    out.push(',');
}

/// The JSON the frontend consumes over /poll, /ws and /stream.
pub fn event_json(e: &Entry) -> String {
    let mut o = String::with_capacity(192 + e.message.len());
    o.push('{');
    field(&mut o, "received_at", &rfc3339_nano(e.received_at));
    field(&mut o, "hostname", &e.hostname);
    field(&mut o, "app_name", &e.app_name);
    field(&mut o, "proc_id", &e.proc_id);
    o.push_str(&format!("\"severity\":{},", e.severity));
    field(&mut o, "severity_name", severity_name(e.severity));
    field(&mut o, "facility_name", facility_name(e.facility));
    field(&mut o, "source_ip", &e.source_ip);
    o.push_str("\"message\":");
    push_str(&mut o, &e.message);
    o.push('}');
    o
}

/// One `JSONEachRow` line for the ClickHouse INSERT (all table columns).
pub fn row_json(e: &Entry, out: &mut String) {
    out.push('{');
    field(out, "received_at", &rfc3339_millis(e.received_at));
    out.push_str(&format!("\"facility\":{},", e.facility));
    field(out, "facility_name", facility_name(e.facility));
    out.push_str(&format!("\"severity\":{},", e.severity));
    field(out, "severity_name", severity_name(e.severity));
    field(out, "hostname", &e.hostname);
    field(out, "app_name", &e.app_name);
    field(out, "proc_id", &e.proc_id);
    field(out, "msg_id", &e.msg_id);
    field(out, "source_ip", &e.source_ip);
    out.push_str("\"message\":");
    push_str(out, &e.message);
    out.push_str("}\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn epoch_and_known_date() {
        assert_eq!(rfc3339_nano(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2026-09-24T18:44:44.5Z
        let t = UNIX_EPOCH + Duration::new(1_790_275_484, 500_000_000);
        assert_eq!(rfc3339_nano(t), "2026-09-24T18:44:44.5Z");
        assert_eq!(rfc3339_millis(t), "2026-09-24T18:44:44.500Z");
    }

    #[test]
    fn leap_day() {
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(rfc3339_nano(t), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn escaping() {
        let mut s = String::new();
        push_str(&mut s, "a\"b\\c\n<&>\u{1}");
        assert_eq!(s, "\"a\\\"b\\\\c\\n\\u003c\\u0026\\u003e\\u0001\"");
    }
}
