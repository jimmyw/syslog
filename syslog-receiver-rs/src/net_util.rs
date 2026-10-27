//! Listener setup via socket2, so IPv6 sockets can be bound v6-only alongside
//! their IPv4 counterparts on the same port.

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};

fn socket(addr: SocketAddr, ty: Type, proto: Protocol) -> std::io::Result<Socket> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, ty, Some(proto))?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock)
}

pub fn udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = socket(addr, Type::DGRAM, Protocol::UDP)?;
    // Absorb bursts; the kernel caps this at net.core.rmem_max.
    let _ = sock.set_recv_buffer_size(8 << 20);
    UdpSocket::from_std(sock.into())
}

pub fn tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let sock = socket(addr, Type::STREAM, Protocol::TCP)?;
    sock.listen(1024)?;
    TcpListener::from_std(sock.into())
}
