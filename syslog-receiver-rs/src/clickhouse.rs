//! Batch writer: buffers rows and INSERTs them via ClickHouse's HTTP interface
//! (`FORMAT JSONEachRow`).

use crate::json::row_json;
use crate::store::Msg;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

pub enum Cmd {
    Entry(Arc<Msg>),
    Shutdown(oneshot::Sender<()>),
}

const BATCH_SIZE: usize = 1000;
const FLUSH_EVERY: Duration = Duration::from_secs(2);

struct Ch {
    client: reqwest::Client,
    base: String,
}

impl Ch {
    async fn query(&self, sql: &str, extra: &str, body: String) -> Result<(), String> {
        let url = format!("{}/?query={}{}", self.base, utf8_percent_encode(sql, NON_ALPHANUMERIC), extra);
        // Explicit length: an empty body is otherwise sent without one, which
        // ClickHouse rejects with 411.
        let resp = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_LENGTH, body.len())
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        // Always drain the body so the connection can go back to the pool.
        let text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {status}: {}", text.trim()))
        }
    }
}

async fn wait_ready(ch: &Ch, table: &str) {
    for i in 1..=30 {
        // `logs` itself is created by clickhouse/init.sql; only alt tables
        // (e.g. a side-by-side comparison run) need creating here.
        let r = match ch.query("SELECT 1", "", String::new()).await {
            Ok(()) if table == "logs" => Ok(()),
            Ok(()) => ch.query(&format!("CREATE TABLE IF NOT EXISTS syslog.{table} AS syslog.logs"), "", String::new()).await,
            Err(e) => Err(e),
        };
        match r {
            Ok(()) => {
                println!("connected to ClickHouse at {}, writing to syslog.{table}", ch.base);
                return;
            }
            Err(e) => {
                eprintln!("waiting for ClickHouse ({i}/30): {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
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
    let extra = "&date_time_input_format=best_effort";
    let mut res = ch.query(&sql, extra, body.clone()).await;
    if let Err(e) = &res {
        // One retry covers a connection dropped mid-request. If ClickHouse had
        // already committed the first attempt this duplicates the batch, which
        // is preferable to losing it.
        eprintln!("batch send error, retrying: {e}");
        tokio::time::sleep(Duration::from_secs(1)).await;
        res = ch.query(&sql, extra, body).await;
    }
    match res {
        Ok(()) => println!("flushed {} log entries", batch.len()),
        Err(e) => eprintln!("batch send error: {e} (dropped {} rows)", batch.len()),
    }
    batch.clear();
}

pub async fn run(host: String, table: String, rx: flume::Receiver<Cmd>) {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build HTTP client");
    let ch = Ch { client, base: format!("http://{host}:8123") };
    wait_ready(&ch, &table).await;

    let mut batch: Vec<Arc<Msg>> = Vec::with_capacity(BATCH_SIZE);
    let mut last_flush = Instant::now();
    loop {
        let wait = FLUSH_EVERY.saturating_sub(last_flush.elapsed());
        match tokio::time::timeout(wait, rx.recv_async()).await {
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
