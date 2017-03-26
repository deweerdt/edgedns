use bytes::{Bytes, BytesMut};
use cache::Cache;
use client_query::*;
use coarsetime::Instant;
use dns;
use futures::Future;
use futures::future::{Loop, loop_fn};
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
    event_loop: Core,
    socket: UdpSocket,
    resolver_tx: Sender<ClientQuery>,
    service_ready_tx: mpsc::SyncSender<u8>,
    cache: Cache,
    varz: Arc<Varz>,
}

#[derive(Debug)]
struct UdpClientSession {
    packet: Option<Vec<u8>>,
    socket: Option<UdpSocket>,
}

impl UdpListener {
    fn run(mut self) -> io::Result<()> {
        debug!("udp listener socket={:?}", self.socket);

        let packet = vec![0u8; DNS_MAX_UDP_SIZE];
        let session = UdpClientSession {
            packet: Some(packet),
            socket: Some(self.socket),
        };
        let stream = loop_fn::<_, UdpClientSession, _, _>(session, move |mut session| {
            println!("loop turn");
            session.socket
                .take()
                .unwrap()
                .recv_dgram(session.packet.take().unwrap())
                .map(move |(socket, packet, len, addr)| (session, socket, packet))
                .and_then(move |(mut session, socket, packet)| {
                              println!("received");
                              session.packet = Some(packet);
                              session.socket = Some(socket);
                              Ok(Loop::Continue(session))
                          })
        });

        self.event_loop.handle().spawn(stream.map_err(|_| {}).map(|_| {}));
        self.service_ready_tx.send(0).unwrap();
        loop {
            self.event_loop.turn(None)
        }
        Ok(())
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
                    event_loop,
                    socket: udp_socket,
                    resolver_tx,
                    service_ready_tx,
                    cache,
                    varz,
                };
                udp_listener.run().expect("Unable to spawn a UDP listener");
            })
            .unwrap();
        info!("UDP listener is ready");
        Ok(udp_listener_th)
    }
}
