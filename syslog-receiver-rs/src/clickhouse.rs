//! Batch writer: buffers rows and INSERTs them via ClickHouse's HTTP interface
//! (`FORMAT JSONEachRow`) using monoio-http-client, so all IO stays on io_uring.

use crate::json::row_json;
use crate::store::Msg;
use bytes::Bytes;
use monoio_http_client::Client;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub enum Cmd {
    Entry(Arc<Msg>),
    Shutdown(std::sync::mpsc::Sender<()>),
}

const BATCH_SIZE: usize = 1000;
const FLUSH_EVERY: Duration = Duration::from_secs(2);

struct Ch {
    client: Client,
    base: String,
}

impl Ch {
    async fn query(&self, sql: &str, extra: &str, body: Bytes) -> Result<(), String> {
        let url = format!("{}/?query={}{}", self.base, utf8_percent_encode(sql, NON_ALPHANUMERIC), extra);
        let resp = self.client.post(url).send_body(body).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        if status.is_success() {
            let _ = resp.bytes().await;
            Ok(())
        } else {
            let text = resp.bytes().await.map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
            Err(format!("HTTP {status}: {}", text.trim()))
        }
    }
}

async fn wait_ready(ch: &Ch, table: &str) {
    for i in 1..=30 {
        // `logs` itself is created by clickhouse/init.sql; only alt tables
        // (e.g. a side-by-side comparison run) need creating here.
        let r = match ch.query("SELECT 1", "", Bytes::new()).await {
            Ok(()) if table == "logs" => Ok(()),
            Ok(()) => ch.query(&format!("CREATE TABLE IF NOT EXISTS syslog.{table} AS syslog.logs"), "", Bytes::new()).await,
            Err(e) => Err(e),
        };
        match r {
            Ok(()) => {
                println!("connected to ClickHouse at {}, writing to syslog.{table}", ch.base);
                return;
            }
            Err(e) => {
                eprintln!("waiting for ClickHouse ({i}/30): {e}");
                monoio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    eprintln!("could not connect to ClickHouse");
    std::process::exit(1);
}

async fn flush(ch: &Ch, table: &str, batch: &mut Vec<Arc<Msg>>) {
    if batch.is_empty() {
        return;
    }
    let mut body = String::with_capacity(batch.len() * 256);
    for m in batch.iter() {
        row_json(&m.entry, &mut body);
    }
    let sql = format!("INSERT INTO syslog.{table} FORMAT JSONEachRow");
    match ch.query(&sql, "&date_time_input_format=best_effort", Bytes::from(body)).await {
        Ok(()) => println!("flushed {} log entries", batch.len()),
        Err(e) => eprintln!("batch send error: {e} (dropped {} rows)", batch.len()),
    }
    batch.clear();
}

pub async fn run(host: String, table: String, rx: flume::Receiver<Cmd>) {
    let ch = Ch { client: Client::builder().http1_client().build(), base: format!("http://{host}:8123") };
    wait_ready(&ch, &table).await;

    let mut batch: Vec<Arc<Msg>> = Vec::with_capacity(BATCH_SIZE);
    let mut last_flush = Instant::now();
    loop {
        let wait = FLUSH_EVERY.saturating_sub(last_flush.elapsed());
        match monoio::time::timeout(wait, rx.recv_async()).await {
            Ok(Ok(Cmd::Entry(m))) => {
                batch.push(m);
                if batch.len() >= BATCH_SIZE {
                    flush(&ch, &table, &mut batch).await;
                    last_flush = Instant::now();
                }
            }
            Ok(Ok(Cmd::Shutdown(ack))) => {
                flush(&ch, &table, &mut batch).await;
                let _ = ack.send(());
                return;
            }
            Ok(Err(_)) => {
                flush(&ch, &table, &mut batch).await;
                return;
            }
            Err(_) => {
                flush(&ch, &table, &mut batch).await;
                last_flush = Instant::now();
            }
        }
    }
}
