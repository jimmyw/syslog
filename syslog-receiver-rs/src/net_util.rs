//! SO_REUSEPORT socket setup so each worker thread gets its own kernel-level
//! accept/recv queue on the same port (thread-per-core fan-out).

use monoio::net::{udp::UdpSocket, TcpListener};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

pub fn udp_reuseport(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

pub fn tcp_reuseport(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    TcpListener::from_std(sock.into())
}
