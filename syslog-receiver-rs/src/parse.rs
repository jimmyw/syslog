//! Port of the Go receiver's syslog parsing (`parseSyslog` and helpers) so both
//! implementations produce identical rows for identical input.

use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub received_at: SystemTime,
    pub facility: u8,
    pub severity: u8,
    pub hostname: String,
    pub app_name: String,
    pub proc_id: String,
    pub msg_id: String,
    pub message: String,
    pub source_ip: String,
}

pub const SEVERITY_NAMES: [&str; 8] = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
pub const FACILITY_NAMES: [&str; 24] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp",
    "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

pub fn severity_name(s: u8) -> &'static str {
    SEVERITY_NAMES.get(s as usize).copied().unwrap_or("unknown")
}

pub fn facility_name(f: u8) -> &'static str {
    FACILITY_NAMES.get(f as usize).copied().unwrap_or("unknown")
}

fn parse_priority(s: &str) -> (u8, u8) {
    match s.parse::<i64>() {
        Ok(n) if (0..=191).contains(&n) => ((n / 8) as u8, (n % 8) as u8),
        _ => (1, 6),
    }
}

/// `s[n..]` but tolerant of `n` landing inside a multi-byte character.
fn tail(s: &str, mut n: usize) -> &str {
    while n < s.len() && !s.is_char_boundary(n) {
        n += 1;
    }
    if n >= s.len() {
        ""
    } else {
        &s[n..]
    }
}

/// Advance past the RFC5424 STRUCTURED-DATA field and return the MSG part.
fn skip_structured_data(s: &str) -> &str {
    let b = s.as_bytes();
    if b.is_empty() {
        return "";
    }
    if b[0] == b'-' {
        return if b.len() > 2 { tail(s, 2) } else { "" };
    }
    if b[0] != b'[' {
        return s;
    }
    let mut i = 0;
    while i < b.len() && b[i] == b'[' {
        let mut in_quote = false;
        i += 1;
        let mut closed = false;
        while i < b.len() {
            let c = b[i];
            if c == b'\\' && in_quote && i + 1 < b.len() {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_quote = !in_quote;
            } else if c == b']' && !in_quote {
                i += 1;
                closed = true;
                break;
            }
            i += 1;
        }
        if !closed {
            break;
        }
        if i < b.len() && b[i] == b' ' {
            i += 1;
            if i >= b.len() || b[i] != b'[' {
                return tail(s, i);
            }
        }
    }
    tail(s, i)
}

/// True only for tokens that plausibly are a hostname/IP in an RFC3164 message.
fn looks_like_hostname(s: &str) -> bool {
    if s.is_empty() || s == "-" {
        return false;
    }
    if s.contains(['[', ']']) {
        return false;
    }
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }
    if s.contains(['.', '-']) {
        return true;
    }
    if s.chars().count() >= 6 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return true;
    }
    false
}

pub fn parse_syslog(raw: &str, src_ip: &str, now: SystemTime) -> Entry {
    let mut e = Entry {
        received_at: now,
        facility: 1,
        severity: 6,
        hostname: "unknown".into(),
        app_name: "-".into(),
        proc_id: "-".into(),
        msg_id: "-".into(),
        message: String::new(),
        source_ip: src_ip.into(),
    };

    let mut s = raw.trim();

    if s.len() > 3 && s.as_bytes()[0] == b'<' {
        if let Some(end) = s.find('>') {
            if end > 0 {
                (e.facility, e.severity) = parse_priority(&s[1..end]);
                s = &s[end + 1..];
            }
        }
    }

    // RFC5424: 1 TIMESTAMP HOSTNAME APP-NAME PROCID [MSGID] STRUCTURED-DATA [MSG]
    if s.len() >= 2 && s.as_bytes()[0] == b'1' && s.as_bytes()[1] == b' ' {
        let fields: Vec<&str> = s[2..].splitn(6, ' ').collect();
        if fields.len() >= 5 {
            e.hostname = match fields[1] {
                "" | "-" => src_ip.to_string(),
                h => h.to_string(),
            };
            if fields[2] != "-" {
                e.app_name = fields[2].to_string();
            }
            e.proc_id = fields[3].to_string();

            let sd_and_msg: String = if fields.len() == 6 {
                if fields[4].starts_with('[') {
                    format!("{} {}", fields[4], fields[5])
                } else {
                    e.msg_id = fields[4].to_string();
                    fields[5].to_string()
                }
            } else {
                fields[4].to_string()
            };
            e.message = skip_structured_data(&sd_and_msg).to_string();
            return e;
        }
    }

    // RFC3164: Mmm DD HH:MM:SS [HOSTNAME] TAG: MSG
    if s.len() >= 15 {
        let rest = tail(s, 15).trim();
        if let Some(space) = rest.find(' ') {
            let candidate = &rest[..space];
            let mut msg = rest[space + 1..].trim();

            if looks_like_hostname(candidate) {
                e.hostname = candidate.to_string();
            } else {
                e.hostname = src_ip.to_string();
                msg = rest;
            }

            match msg.find(':') {
                Some(colon) if colon > 0 => {
                    let tag = &msg[..colon];
                    match tag.find('[') {
                        Some(br) if br > 0 => {
                            e.app_name = tag[..br].to_string();
                            e.proc_id = tag[br..].trim_matches(|c| c == '[' || c == ']').to_string();
                        }
                        _ => e.app_name = tag.to_string(),
                    }
                    e.message = msg[colon + 1..].trim().to_string();
                }
                _ => e.message = msg.to_string(),
            }
        } else {
            e.hostname = src_ip.to_string();
            e.message = rest.to_string();
        }
        return e;
    }

    eprintln!("WARN: unrecognised syslog format from {}: {:.120}", src_ip, raw);
    e.hostname = src_ip.to_string();
    e.message = s.to_string();
    e
}

/// Convert IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4 text.
pub fn normalize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        v4 => v4.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(raw: &str) -> Entry {
        parse_syslog(raw, "10.0.0.9", SystemTime::UNIX_EPOCH)
    }

    #[test]
    fn rfc3164_with_host_tag_pid() {
        let e = p("<134>Jun  9 12:34:56 esp32-kitchen app[1]: Temperature: 23.4C");
        assert_eq!((e.facility, e.severity), (16, 6));
        assert_eq!(e.hostname, "esp32-kitchen");
        assert_eq!(e.app_name, "app");
        assert_eq!(e.proc_id, "1");
        assert_eq!(e.message, "Temperature: 23.4C");
    }

    #[test]
    fn rfc3164_without_hostname_uses_source_ip() {
        let e = p("<13>Jun  9 12:34:56 Downloading firmware: 50%");
        assert_eq!(e.hostname, "10.0.0.9");
        assert_eq!(e.app_name, "Downloading firmware");
    }

    #[test]
    fn rfc3164_hex_container_id_is_hostname() {
        let e = p("<14>Jun  9 12:34:56 ec6260604234 nginx: hello");
        assert_eq!(e.hostname, "ec6260604234");
        assert_eq!(e.app_name, "nginx");
    }

    #[test]
    fn rfc5424_full() {
        let e = p("<165>1 2026-01-01T00:00:00Z host1 app 42 ID47 [ex@1 a=\"b c\"] the message");
        assert_eq!((e.facility, e.severity), (20, 5));
        assert_eq!(e.hostname, "host1");
        assert_eq!(e.app_name, "app");
        assert_eq!(e.proc_id, "42");
        assert_eq!(e.msg_id, "ID47");
        assert_eq!(e.message, "the message");
    }

    #[test]
    fn rfc5424_nil_sd_and_missing_msgid() {
        let e = p("<14>1 2026-01-01T00:00:00Z host1 app 42 - - hello world");
        assert_eq!(e.msg_id, "-");
        assert_eq!(e.message, "hello world");
        let e = p("<14>1 2026-01-01T00:00:00Z host1 app 42 [x a=\"1\"] hello");
        assert_eq!(e.msg_id, "-");
        assert_eq!(e.message, "hello");
    }

    #[test]
    fn rfc5424_multiple_sd_elements() {
        let e = p("<14>1 2026-01-01T00:00:00Z h a 1 M [a x=\"] \"][b y=\"2\"] msg body");
        assert_eq!(e.message, "msg body");
    }

    #[test]
    fn rfc5424_dash_hostname_uses_source_ip() {
        let e = p("<14>1 2026-01-01T00:00:00Z - app 1 M - m");
        assert_eq!(e.hostname, "10.0.0.9");
    }

    #[test]
    fn bad_priority_defaults() {
        let e = p("<999>Jun  9 12:34:56 host-1 tag: m");
        assert_eq!((e.facility, e.severity), (1, 6));
        assert_eq!(e.hostname, "host-1");
    }

    #[test]
    fn short_garbage_falls_back() {
        let e = p("hi");
        assert_eq!(e.hostname, "10.0.0.9");
        assert_eq!(e.message, "hi");
    }

    #[test]
    fn ipv4_mapped_normalised() {
        assert_eq!(normalize_ip("::ffff:1.2.3.4".parse().unwrap()), "1.2.3.4");
    }
}
