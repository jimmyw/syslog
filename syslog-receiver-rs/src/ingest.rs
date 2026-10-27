//! UDP and TCP syslog ingest. Each received message is parsed, published to the
//! in-memory store/hub (live endpoints) and queued for the ClickHouse writer.

use crate::clickhouse::Cmd;
use crate::json::event_json;
use crate::parse::{normalize_ip, parse_syslog};
use crate::store::{Msg, Shared};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
    let mut buf = vec![0u8; 65536];
    loop {
        match sock.recv_from(&mut buf).await {
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
                tokio::spawn(tcp_conn(stream, normalize_ip(addr.ip()), ctx.clone()));
            }
            Err(e) => {
                // Transient (e.g. EMFILE); keep accepting rather than going deaf.
                eprintln!("tcp accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn tcp_conn(mut stream: TcpStream, src_ip: String, ctx: Ctx) {
    let mut buf = vec![0u8; 65536];
    let mut acc: Vec<u8> = Vec::new();
    loop {
        match stream.read(&mut buf).await {
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
