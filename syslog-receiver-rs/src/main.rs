mod clickhouse;
mod config;
mod filter;
mod http;
mod ingest;
mod json;
mod net_util;
mod parse;
mod store;

use config::Config;
use ingest::Ctx;
use std::sync::Arc;

fn worker(id: usize, cfg_workers: usize, syslog_port: u16, http_port: u16, shared: Arc<store::Shared>, tx: flume::Sender<clickhouse::Cmd>) {
    let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
        .expect("failed to build monoio runtime (io_uring unavailable? check kernel >= 5.19 and seccomp=unconfined)");

    rt.block_on(async move {
        let ctx = Ctx { shared: shared.clone(), tx };

        if let Ok(s) = net_util::udp_reuseport(([0, 0, 0, 0], syslog_port).into()) {
            monoio::spawn(ingest::udp_loop(s, ctx.clone()));
        } else if id == 0 {
            eprintln!("UDP IPv4 listen :{syslog_port} failed");
        }
        if let Ok(s) = net_util::udp_reuseport(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, syslog_port, 0, 0))) {
            monoio::spawn(ingest::udp_loop(s, ctx.clone()));
        }
        if let Ok(l) = net_util::tcp_reuseport(([0, 0, 0, 0], syslog_port).into()) {
            monoio::spawn(ingest::tcp_accept_loop(l, ctx.clone()));
        } else if id == 0 {
            eprintln!("TCP IPv4 listen :{syslog_port} failed");
        }
        if let Ok(l) = net_util::tcp_reuseport(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, syslog_port, 0, 0))) {
            monoio::spawn(ingest::tcp_accept_loop(l, ctx.clone()));
        }

        match net_util::tcp_reuseport(([0, 0, 0, 0], http_port).into()) {
            Ok(l) => {
                if id == 0 {
                    println!("worker 0/{cfg_workers}: HTTP listening on :{http_port}, syslog on :{syslog_port} (UDP+TCP, v4+v6)");
                }
                http::serve(l, shared).await;
            }
            Err(e) => eprintln!("HTTP listen :{http_port} failed: {e}"),
        }
    });
}

fn main() {
    let cfg = Config::from_env();
    println!("syslog-receiver-rs starting: table=syslog.{} workers={}", cfg.table, cfg.workers);

    let shared = store::Shared::new(10_000);
    let (tx, rx) = flume::unbounded::<clickhouse::Cmd>();

    let ch_host = cfg.clickhouse_host.clone();
    let ch_table = cfg.table.clone();
    let ch_thread = std::thread::Builder::new()
        .name("clickhouse-writer".into())
        .spawn(move || {
            let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                .enable_timer()
                .build()
                .expect("failed to build monoio runtime for clickhouse writer");
            rt.block_on(clickhouse::run(ch_host, ch_table, rx));
        })
        .expect("spawn clickhouse-writer thread");

    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    {
        let tx = tx.clone();
        ctrlc_like(move || {
            println!("shutting down...");
            let (ack_tx, ack_rx) = std::sync::mpsc::channel();
            let _ = tx.send(clickhouse::Cmd::Shutdown(ack_tx));
            let _ = ack_rx.recv_timeout(std::time::Duration::from_secs(10));
            let _ = shutdown_tx.send(());
        });
    }

    let mut handles = Vec::new();
    for id in 1..cfg.workers {
        let shared = shared.clone();
        let tx = tx.clone();
        let (syslog_port, http_port) = (cfg.syslog_port, cfg.http_port);
        let n = cfg.workers;
        handles.push(std::thread::Builder::new().name(format!("worker-{id}")).spawn(move || worker(id, n, syslog_port, http_port, shared, tx)).unwrap());
    }

    // Worker 0 runs on the main thread; drop `tx` here once workers hold their
    // own clones so the writer's channel closes on shutdown.
    let n = cfg.workers;
    let (sp, hp) = (cfg.syslog_port, cfg.http_port);
    let main_tx = tx.clone();
    drop(tx);
    let main_shared = shared;
    let w0 = std::thread::Builder::new().name("worker-0".into()).spawn(move || worker(0, n, sp, hp, main_shared, main_tx)).unwrap();

    let _ = shutdown_rx.recv();
    drop(w0);
    drop(handles);
    let _ = ch_thread.join();
}

/// SIGINT/SIGTERM -> callback, off the async runtimes (signal-hook uses a plain
/// blocking OS thread), matching the Go receiver's `os/signal` + final-flush behaviour.
fn ctrlc_like(f: impl FnOnce() + Send + 'static) {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;
    std::thread::spawn(move || {
        if let Ok(mut signals) = Signals::new([SIGINT, SIGTERM]) {
            if signals.forever().next().is_some() {
                f();
            }
        }
    });
}
