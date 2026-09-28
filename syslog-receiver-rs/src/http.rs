//! Minimal HTTP/1.1 handling for /poll, /stream (SSE) and /ws.
//! Requests are parsed with `httparse`; WebSocket framing is `monoio-tungstenite`.
//! (No hand-rolled HTTP parser or WS framing — only the thin routing glue is ours.)

use crate::filter::{parse_query, Filter};
use crate::store::Shared;
use monoio::io::{sink::SinkExt, stream::Stream as MStream, AsyncReadRent, AsyncWriteRentExt};
use monoio::net::{TcpListener, TcpStream};
use monoio::time::{interval, timeout};
use monoio_tungstenite::{handshake::derive_accept_key, protocol::Role, Message, WebSocket};
use std::sync::Arc;
use std::time::Duration;

pub async fn serve(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                monoio::spawn(handle_conn(stream, shared.clone()));
            }
            Err(e) => {
                eprintln!("http accept error: {e}");
                return;
            }
        }
    }
}

struct Req {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
}

async fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    loop {
        let mut chunk = vec![0u8; 4096];
        let (res, c) = stream.read(chunk).await;
        chunk = c;
        let n = match res {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 32 * 1024 {
            return None;
        }
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(_)) => {
                let (path, query) = req.path.unwrap_or("/").split_once('?').unwrap_or((req.path.unwrap_or("/"), ""));
                return Some(Req {
                    method: req.method.unwrap_or("").to_string(),
                    path: path.to_string(),
                    query: query.to_string(),
                    headers: req
                        .headers
                        .iter()
                        .map(|h| (h.name.to_ascii_lowercase(), String::from_utf8_lossy(h.value).into_owned()))
                        .collect(),
                });
            }
            Ok(httparse::Status::Partial) => continue,
            Err(_) => return None,
        }
    }
}

fn header<'a>(req: &'a Req, name: &str) -> Option<&'a str> {
    req.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

async fn write_all(stream: &mut TcpStream, data: Vec<u8>) -> bool {
    let (res, _) = stream.write_all(data).await;
    res.is_ok()
}

async fn handle_conn(mut stream: TcpStream, shared: Arc<Shared>) {
    let _ = stream.set_nodelay(true);
    let Some(req) = read_request(&mut stream).await else { return };
    if req.method != "GET" {
        let _ = write_all(&mut stream, b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()).await;
        return;
    }

    match req.path.as_str() {
        "/poll" => poll(stream, &req, shared).await,
        "/stream" => sse(stream, &req, shared).await,
        "/ws" => ws(stream, &req, shared).await,
        _ => {
            let _ = write_all(&mut stream, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()).await;
        }
    }
}

// ── /poll ──────────────────────────────────────────────────────────────────

async fn poll(mut stream: TcpStream, req: &Req, shared: Arc<Shared>) {
    let q = parse_query(&req.query);
    let filter = Filter::from_query(&q);
    let seq_param = crate::filter::get(&q, "seq");

    let body = if let Some(seq_param) = seq_param {
        let Ok(after) = seq_param.parse::<u64>() else {
            let _ = write_all(&mut stream, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\ninvalid seq".to_vec()).await;
            return;
        };
        let burst_ms: u64 = crate::filter::get(&q, "burst").and_then(|b| b.parse().ok()).unwrap_or(100);

        let (entries, next) = shared.since(after);
        let (entries, next) = if !entries.is_empty() {
            (entries, next)
        } else {
            let sub = shared.subscribe();
            let (entries, next) = shared.since(after);
            if !entries.is_empty() {
                (entries, next)
            } else {
                if let Ok(Ok(_)) = timeout(Duration::from_secs(30), sub.rx.recv_async()).await {
                    let _ = timeout(Duration::from_millis(burst_ms), async {
                        loop {
                            if sub.rx.recv_async().await.is_err() {
                                break;
                            }
                        }
                    })
                    .await;
                }
                shared.since(after)
            }
        };
        let logs: Vec<&str> = entries.iter().filter(|m| filter.matches(&m.entry)).map(|m| m.json.as_str()).collect();
        format!("{{\"seq\":{next},\"logs\":[{}]}}", logs.join(","))
    } else {
        format!("{{\"seq\":{},\"logs\":[]}}", shared.current_seq())
    };

    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = write_all(&mut stream, resp.into_bytes()).await;
}

// ── /stream (SSE) ────────────────────────────────────────────────────────────

async fn sse(mut stream: TcpStream, req: &Req, shared: Arc<Shared>) {
    let filter = Filter::from_query(&parse_query(&req.query));
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    if !write_all(&mut stream, head).await {
        return;
    }
    let sub = shared.subscribe();
    loop {
        match sub.rx.recv_async().await {
            Ok(msg) => {
                if !filter.matches(&msg.entry) {
                    continue;
                }
                let data = format!("data: {}\n\n", msg.json);
                let chunk = format!("{:x}\r\n{}\r\n", data.len(), data);
                if !write_all(&mut stream, chunk.into_bytes()).await {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

// ── /ws ────────────────────────────────────────────────────────────────────

async fn ws(mut stream: TcpStream, req: &Req, shared: Arc<Shared>) {
    let Some(key) = header(req, "sec-websocket-key") else {
        let _ = write_all(&mut stream, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()).await;
        return;
    };
    let accept = derive_accept_key(key.as_bytes());
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    if !write_all(&mut stream, resp.into_bytes()).await {
        return;
    }

    let filter = Filter::from_query(&parse_query(&req.query));
    let mut wsock = WebSocket::from_raw_socket(stream, Role::Server, None);
    let sub = shared.subscribe();
    let mut ping = interval(Duration::from_secs(30));

    loop {
        monoio::select! {
            incoming = wsock.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => return,
                    Some(Err(_)) => return,
                    Some(Ok(_)) => {} // client sends nothing meaningful; ignore
                }
            },
            entry = sub.rx.recv_async() => {
                match entry {
                    Ok(msg) if filter.matches(&msg.entry) => {
                        if wsock.send_and_flush(Message::text(msg.json.clone())).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            },
            _ = ping.tick() => {
                if wsock.send_and_flush(Message::Ping(Vec::new().into())).await.is_err() {
                    return;
                }
            },
        }
    }
}
