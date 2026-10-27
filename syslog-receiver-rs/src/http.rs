//! /poll, /stream (SSE) and /ws, served with axum.

use crate::filter::{parse_query, Filter};
use crate::store::Shared;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{RawQuery, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, timeout};

type Q = RawQuery;
const CORS: (header::HeaderName, &str) = (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");

pub fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/poll", get(poll))
        .route("/stream", get(sse))
        .route("/ws", get(ws))
        .with_state(shared)
}

fn query(q: &Q) -> Vec<(String, String)> {
    parse_query(q.0.as_deref().unwrap_or(""))
}

// ── /poll ──────────────────────────────────────────────────────────────────

async fn poll(State(shared): State<Arc<Shared>>, q: Q) -> Response {
    let q = query(&q);
    let filter = Filter::from_query(&q);

    let body = if let Some(seq_param) = crate::filter::get(&q, "seq") {
        let Ok(after) = seq_param.parse::<u64>() else {
            return (StatusCode::BAD_REQUEST, "invalid seq").into_response();
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
                    let _ = timeout(Duration::from_millis(burst_ms), async { while sub.rx.recv_async().await.is_ok() {} }).await;
                }
                shared.since(after)
            }
        };
        let logs: Vec<&str> = entries.iter().filter(|m| filter.matches(&m.entry)).map(|m| m.json.as_str()).collect();
        format!("{{\"seq\":{next},\"logs\":[{}]}}", logs.join(","))
    } else {
        format!("{{\"seq\":{},\"logs\":[]}}", shared.current_seq())
    };

    ([(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-cache"), CORS], body).into_response()
}

// ── /stream (SSE) ────────────────────────────────────────────────────────────

async fn sse(State(shared): State<Arc<Shared>>, q: Q) -> Response {
    let filter = Filter::from_query(&query(&q));
    let sub = shared.subscribe();
    let events = futures_util::stream::unfold((sub, filter), |(sub, filter)| async move {
        loop {
            match sub.rx.recv_async().await {
                Ok(msg) if filter.matches(&msg.entry) => {
                    let ev = Event::default().data(msg.json.as_str());
                    return Some((Ok::<_, Infallible>(ev), (sub, filter)));
                }
                Ok(_) => {}
                Err(_) => return None,
            }
        }
    });
    ([CORS], Sse::new(events)).into_response()
}

// ── /ws ────────────────────────────────────────────────────────────────────

async fn ws(State(shared): State<Arc<Shared>>, q: Q, upgrade: WebSocketUpgrade) -> Response {
    let filter = Filter::from_query(&query(&q));
    upgrade.on_upgrade(move |sock| ws_conn(sock, filter, shared))
}

async fn ws_conn(mut sock: WebSocket, filter: Filter, shared: Arc<Shared>) {
    let sub = shared.subscribe();
    let mut ping = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            incoming = sock.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                    Some(Ok(_)) => {} // client sends nothing meaningful; ignore
                }
            },
            entry = sub.rx.recv_async() => {
                match entry {
                    Ok(msg) if filter.matches(&msg.entry) => {
                        if sock.send(Message::text(msg.json.as_str())).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => return,
                }
            },
            _ = ping.tick() => {
                if sock.send(Message::Ping(Default::default())).await.is_err() {
                    return;
                }
            },
        }
    }
}
