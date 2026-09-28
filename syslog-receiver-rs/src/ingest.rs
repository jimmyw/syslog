//! UDP and TCP syslog ingest. Each received message is parsed, published to the
//! in-memory store/hub (live endpoints) and queued for the ClickHouse writer.

use crate::clickhouse::Cmd;
use crate::json::event_json;
use crate::parse::{normalize_ip, parse_syslog};
use crate::store::{Msg, Shared};
use monoio::io::AsyncReadRent;
use monoio::net::{udp::UdpSocket, TcpListener};
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Clone)]
pub struct Ctx {
    pub shared: Arc<Shared>,
    pub tx: flume::Sender<Cmd>,
}

impl Ctx {
    fn ingest(&self, raw: &[u8], src_ip: &str) {
        let text = String::from_utf8_lossy(raw);
        let entry = parse_syslog(&text, src_ip, SystemTime::now());
        let json = event_json(&entry);
        let msg = Arc::new(Msg { entry, json });
        self.shared.publish(msg.clone());
        let _ = self.tx.send(Cmd::Entry(msg));
    }
}

pub async fn udp_loop(sock: UdpSocket, ctx: Ctx) {
    let mut buf: Vec<u8> = Vec::with_capacity(65536);
    loop {
        buf.clear();
        let (res, b) = sock.recv_from(buf).await;
        buf = b;
        match res {
            Ok((n, src)) => ctx.ingest(&buf[..n], &normalize_ip(src.ip())),
            Err(e) => {
                eprintln!("udp recv error: {e}");
                return;
            }
        }
    }
}

pub async fn tcp_accept_loop(listener: TcpListener, ctx: Ctx) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                monoio::spawn(tcp_conn(stream, normalize_ip(addr.ip()), ctx.clone()));
            }
            Err(e) => {
                eprintln!("tcp accept error: {e}");
                return;
            }
        }
    }
}

async fn tcp_conn(mut stream: monoio::net::TcpStream, src_ip: String, ctx: Ctx) {
    let mut buf: Vec<u8> = Vec::with_capacity(65536);
    let mut acc: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let (res, b) = stream.read(buf).await;
        buf = b;
        match res {
            Ok(0) | Err(_) => return,
            Ok(n) => acc.extend_from_slice(&buf[..n]),
        }
        let mut start = 0;
        while let Some(i) = acc[start..].iter().position(|&c| c == b'\n') {
            let line = &acc[start..start + i];
            start += i + 1;
            if !line.iter().all(|c| c.is_ascii_whitespace()) {
                ctx.ingest(line, &src_ip);
            }
        }
        acc.drain(..start);
    }
}
