//! Query-string filters shared by /poll, /ws and /stream (same semantics as Go's `wsFilter`).

use crate::parse::Entry;
use percent_encoding::percent_decode_str;

pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

fn decode(s: &str) -> String {
    percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned()
}

pub fn get<'a>(q: &'a [(String, String)], key: &str) -> Option<&'a str> {
    q.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

#[derive(Default, Clone)]
pub struct Filter {
    hostname: String,
    source_ip: String,
    app_name: String,
    message_contains: String,
    severity_max: Option<u8>,
}

impl Filter {
    pub fn from_query(q: &[(String, String)]) -> Self {
        let g = |k| get(q, k).unwrap_or("");
        Filter {
            hostname: g("hostname").to_lowercase(),
            source_ip: g("source_ip").to_string(),
            app_name: g("app_name").to_lowercase(),
            message_contains: g("message_contains").to_lowercase(),
            severity_max: g("severity_max").parse::<i64>().ok().filter(|n| (0..=7).contains(n)).map(|n| n as u8),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hostname.is_empty()
            && self.source_ip.is_empty()
            && self.app_name.is_empty()
            && self.message_contains.is_empty()
            && self.severity_max.is_none()
    }

    pub fn matches(&self, e: &Entry) -> bool {
        if self.is_empty() {
            return true;
        }
        (self.hostname.is_empty() || e.hostname.to_lowercase().contains(&self.hostname))
            && (self.source_ip.is_empty() || e.source_ip == self.source_ip)
            && (self.app_name.is_empty() || e.app_name.to_lowercase() == self.app_name)
            && (self.message_contains.is_empty() || e.message.to_lowercase().contains(&self.message_contains))
            && self.severity_max.is_none_or(|m| e.severity <= m)
    }
}
