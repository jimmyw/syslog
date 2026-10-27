mod clickhouse;
mod config;
mod filter;
mod http;
mod ingest;
mod json;
mod net_util;
mod parse;
mod store;

use axum::serve::ListenerExt;
use config::Config;
use ingest::Ctx;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

fn main() {
    let cfg = Config::from_env();
    println!("syslog-receiver-rs starting: table=syslog.{} workers={}", cfg.table, cfg.workers);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.workers)
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(run(cfg));
}

async fn run(cfg: Config) {
    let shared = store::Shared::new(10_000);
    let (tx, rx) = flume::unbounded::<clickhouse::Cmd>();
    let writer = tokio::spawn(clickhouse::run(cfg.clickhouse_host.clone(), cfg.table.clone(), rx));

    let ctx = Ctx { shared: shared.clone(), tx: tx.clone() };
    let sp = cfg.syslog_port;
    for addr in [SocketAddr::from(([0, 0, 0, 0], sp)), SocketAddr::from((Ipv6Addr::UNSPECIFIED, sp))] {
        match net_util::udp(addr) {
            Ok(s) => drop(tokio::spawn(ingest::udp_loop(s, ctx.clone()))),
            Err(e) => eprintln!("UDP listen {addr} failed: {e}"),
        }
        match net_util::tcp(addr) {
            Ok(l) => drop(tokio::spawn(ingest::tcp_accept_loop(l, ctx.clone()))),
            Err(e) => eprintln!("TCP listen {addr} failed: {e}"),
        }
    }

    let hp = cfg.http_port;
    match net_util::tcp(([0, 0, 0, 0], hp).into()) {
        Ok(l) => {
            println!("HTTP listening on :{hp}, syslog on :{sp} (UDP+TCP, v4+v6)");
            let l = l.tap_io(|tcp| {
                let _ = tcp.set_nodelay(true);
            });
            tokio::spawn(async move {
                if let Err(e) = axum::serve(l, http::router(shared)).await {
                    eprintln!("HTTP server error: {e}");
                }
            });
        }
        Err(e) => eprintln!("HTTP listen :{hp} failed: {e}"),
    }

    shutdown_signal().await;
    println!("shutting down...");
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    let _ = tx.send(clickhouse::Cmd::Shutdown(ack_tx));
    let _ = tokio::time::timeout(Duration::from_secs(10), ack_rx).await;
    writer.abort();
}

/// Resolves on SIGINT or SIGTERM, so the final batch is flushed on `docker stop`.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
}
