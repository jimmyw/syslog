use std::env;

pub struct Config {
    pub clickhouse_host: String,
    pub table: String,
    pub syslog_port: u16,
    pub http_port: u16,
    pub workers: usize,
}

fn var<T: std::str::FromStr>(k: &str, default: T) -> T {
    env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            clickhouse_host: env::var("CLICKHOUSE_HOST").unwrap_or_else(|_| "clickhouse".into()),
            table: env::var("TABLE").unwrap_or_else(|_| "logs_rs".into()),
            syslog_port: var("SYSLOG_PORT", 514),
            http_port: var("HTTP_PORT", 8888),
            workers: var(
                "WORKERS",
                std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            ),
        }
    }
}
