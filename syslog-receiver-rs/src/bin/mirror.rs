//! Fans each UDP/TCP syslog message received on :5514 out to both the Go
//! receiver (:514) and the Rust receiver (:1514) unchanged, so both can be
//! compared on identical input. `mirror replay` re-sends recent ClickHouse
//! rows' raw-ish reconstructed lines through the same fan-out for a repeatable
//! corpus (best-effort — the DB doesn't keep the original raw line, so it's
//! reconstructed as an RFC5424 line from the stored fields).

use monoio::net::udp::UdpSocket;
use monoio_http_client::Client;
use std::env;
use std::net::SocketAddr;

const MIRROR_PORT: u16 = 5514;
const GO_ADDR: &str = "syslog-receiver:514";
const RS_ADDR: &str = "syslog-receiver-rs:1514";

#[monoio::main(enable_timer = true)]
async fn main() {
    if env::args().nth(1).as_deref() == Some("replay") {
        return replay().await;
    }

    let sock = UdpSocket::bind(("0.0.0.0", MIRROR_PORT)).expect("bind :5514");
    let go: SocketAddr = tokio_style_resolve(GO_ADDR);
    let rs: SocketAddr = tokio_style_resolve(RS_ADDR);
    println!("mirror listening on :{MIRROR_PORT}, fanning out to {go} (go) and {rs} (rust)");

    let mut buf = vec![0u8; 65536];
    loop {
        let (res, b) = sock.recv_from(buf).await;
        buf = b;
        let Ok((n, _src)) = res else { continue };
        let payload = buf[..n].to_vec();
        let _ = sock.send_to(payload.clone(), go).await;
        let _ = sock.send_to(payload, rs).await;
    }
}

/// Resolve to an IPv4 address specifically: the mirror's UDP socket is bound
/// to 0.0.0.0, so sending to a resolved IPv6 destination would silently fail.
fn tokio_style_resolve(host_port: &str) -> SocketAddr {
    use std::net::ToSocketAddrs;
    host_port
        .to_socket_addrs()
        .expect("resolve")
        .find(|a| a.is_ipv4())
        .expect("no IPv4 address")
}

/// Pull the most recent rows from ClickHouse and re-send them as RFC5424 lines
/// through the mirror, for a deterministic comparison corpus.
async fn replay() {
    let ch_host = env::var("CLICKHOUSE_HOST").unwrap_or_else(|_| "clickhouse".into());
    let n: u32 = env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let client = Client::builder().http1_client().build();
    let sql = format!(
        "SELECT hostname, app_name, proc_id, msg_id, message, source_ip, facility, severity \
         FROM syslog.logs ORDER BY received_at DESC LIMIT {n} FORMAT JSONEachRow"
    );
    let url = format!(
        "http://{ch_host}:8123/?query={}",
        percent_encoding::utf8_percent_encode(&sql, percent_encoding::NON_ALPHANUMERIC)
    );
    let resp = client.get(url).send().await.expect("clickhouse query");
    let body = resp.bytes().await.expect("read body");

    let sock = UdpSocket::bind(("0.0.0.0", 0)).expect("bind");
    let mirror: SocketAddr = tokio_style_resolve(&format!("localhost:{MIRROR_PORT}"));
    let mut sent = 0;
    for line in String::from_utf8_lossy(&body).lines() {
        let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let pri = row["facility"].as_u64().unwrap_or(1) * 8 + row["severity"].as_u64().unwrap_or(6);
        let msg = format!(
            "<{pri}>1 2026-01-01T00:00:00Z {} {} {} {} - {}",
            row["hostname"].as_str().unwrap_or("-"),
            row["app_name"].as_str().unwrap_or("-"),
            row["proc_id"].as_str().unwrap_or("-"),
            row["msg_id"].as_str().unwrap_or("-"),
            row["message"].as_str().unwrap_or(""),
        );
        let _ = sock.send_to(msg.into_bytes(), mirror).await;
        sent += 1;
    }
    println!("replayed {sent} rows through :{MIRROR_PORT}");
}
