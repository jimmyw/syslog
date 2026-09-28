//! Compares `syslog.logs` (Go) against `syslog.logs_rs` (Rust) over a recent
//! time window and reports missing rows / field mismatches. Matches rows by
//! (source_ip, message) since that pair is stable across both parsers and the
//! `mirror` fan-out preserves the exact same bytes to both receivers.

use monoio_http_client::Client;
use std::collections::HashMap;
use std::env;

#[derive(serde::Deserialize, Debug, Clone, PartialEq)]
struct Row {
    hostname: String,
    app_name: String,
    proc_id: String,
    msg_id: String,
    severity: u8,
    facility: u8,
    source_ip: String,
    message: String,
}

#[monoio::main(enable_timer = true)]
async fn main() {
    let ch_host = env::var("CLICKHOUSE_HOST").unwrap_or_else(|_| "clickhouse".into());
    let since = env::args().nth(1).unwrap_or_else(|| "10 MINUTE".into());
    let client = Client::builder().http1_client().build();

    let go = fetch(&client, &ch_host, "logs", &since).await;
    let rs = fetch(&client, &ch_host, "logs_rs", &since).await;

    let key = |r: &Row| format!("{}\u{0}{}", r.source_ip, r.message);
    let go_map: HashMap<String, Row> = go.iter().map(|r| (key(r), r.clone())).collect();
    let rs_map: HashMap<String, Row> = rs.iter().map(|r| (key(r), r.clone())).collect();

    let mut missing_in_rs = 0;
    let mut mismatched = 0;
    for (k, gr) in &go_map {
        match rs_map.get(k) {
            None => {
                missing_in_rs += 1;
                if missing_in_rs <= 10 {
                    println!("missing in rust: {gr:?}");
                }
            }
            Some(rr) if rr != gr => {
                mismatched += 1;
                if mismatched <= 10 {
                    println!("mismatch:\n  go: {gr:?}\n  rs: {rr:?}");
                }
            }
            _ => {}
        }
    }
    let missing_in_go = go_map.keys().filter(|k| !rs_map.contains_key(*k)).count();
    println!(
        "go={} rust={} missing_in_rust={missing_in_rs} mismatched={mismatched} (rust-only={})",
        go.len(),
        rs.len(),
        rs_map.len().saturating_sub(go_map.len() - missing_in_go)
    );
}

async fn fetch(client: &Client, host: &str, table: &str, since: &str) -> Vec<Row> {
    let sql = format!(
        "SELECT hostname, app_name, proc_id, msg_id, severity, facility, source_ip, message \
         FROM syslog.{table} WHERE received_at >= now() - INTERVAL {since} FORMAT JSONEachRow"
    );
    let url = format!(
        "http://{host}:8123/?query={}",
        percent_encoding::utf8_percent_encode(&sql, percent_encoding::NON_ALPHANUMERIC)
    );
    let resp = client.get(url).send().await.expect("clickhouse query");
    let body = resp.bytes().await.expect("read body");
    String::from_utf8_lossy(&body).lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}
