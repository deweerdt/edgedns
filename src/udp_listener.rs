use bytes::{Bytes, BytesMut};
use cache::Cache;
use client_query::*;
use coarsetime::Instant;
use dns;
use futures::Future;
use futures::future::{self, Loop, loop_fn, FutureResult, BoxFuture};
use futures::sync::mpsc::{channel, Sender, Receiver};
use futures::Sink;
use std::io;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use super::EdgeDNSContext;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Core;
use varz::Varz;

use super::{DNS_MAX_UDP_SIZE, DNS_QUERY_MIN_SIZE, DNS_QUERY_MAX_SIZE};

pub struct UdpListener {
    event_loop: Option<Core>,
    socket: Option<UdpSocket>,
    resolver_tx: Sender<ClientQuery>,
    service_ready_tx: Option<mpsc::SyncSender<u8>>,
    cache: Cache,
    varz: Arc<Varz>,
    packet_buf: Option<Vec<u8>>,
}

struct UdpSession {
    packet_buf: Option<Vec<u8>>,
    socket: Option<UdpSocket>,
}

impl UdpListener {
    fn process(mut session: UdpSession) -> Box<Future<Item = UdpSession, Error = io::Error>> {
        Box::new(session.socket
                     .take()
                     .expect("Empty socket")
                     .recv_dgram(session.packet_buf.take().expect("Empty UDP buffer"))
                     .map(|(socket, packet_buf, _, _)| {
                              session.socket = Some(socket);
                              session.packet_buf = Some(packet_buf);
                              println!("received");
                              session
                          }))
    }

    fn run(mut self) -> io::Result<()> {
        debug!("udp listener socket={:?}", self.socket);
        let mut event_loop = self.event_loop.take().unwrap();
        let service_ready_tx = self.service_ready_tx.take().unwrap();
        let stream = loop_fn::<_, UdpListener, _, _>(UdpSession {
                                                         packet_buf: self.packet_buf,
                                                         socket: self.socket,
                                                     },
                                                     |session| {
                                                         Self::process(session)
                                                    .map(|session| Loop::Continue(session))
                                                     });
        event_loop.handle().spawn(stream.map_err(|_| {}).map(|_| {}));
        service_ready_tx.send(0).unwrap();
        loop {
            event_loop.turn(None)
        }
    }

    pub fn spawn(
        edgedns_context: &EdgeDNSContext,
        resolver_tx: Sender<ClientQuery>,
        service_ready_tx: mpsc::SyncSender<u8>,
    ) -> io::Result<(thread::JoinHandle<()>)> {
        let net_udp_socket = edgedns_context.udp_socket.try_clone()?;
        let cache = edgedns_context.cache.clone();
        let varz = edgedns_context.varz.clone();
        let udp_listener_th = thread::Builder::new()
            .name("udp_listener".to_string())
            .spawn(move || {
                let event_loop = Core::new().unwrap();
                let udp_socket = UdpSocket::from_socket(net_udp_socket, &event_loop.handle())
                    .expect("Unable to use a local UDP listener");
                let udp_listener = UdpListener {
                    event_loop: Some(event_loop),
                    socket: Some(udp_socket),
                    resolver_tx,
                    service_ready_tx: Some(service_ready_tx),
                    cache,
                    varz,
                    packet_buf: Some(vec![0u8; DNS_MAX_UDP_SIZE]),
                };
                udp_listener.run().expect("Unable to spawn a UDP listener");
            })
            .unwrap();
        info!("UDP listener is ready");
        Ok(udp_listener_th)
    }
}
