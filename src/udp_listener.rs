use bytes::{Bytes, BytesMut};
use cache::Cache;
use client_query::*;
use coarsetime::Instant;
use dns;
use futures::Future;
use futures::future::{self, Loop, loop_fn, FutureResult};
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

impl UdpListener {
    fn process(mut self) -> Box<Future<Item = Loop<Self, Self>, Error = io::Error>> {
        Box::new(self.socket
                     .take()
                     .unwrap()
                     .recv_dgram(self.packet_buf.take().unwrap())
                     .and_then(move |(socket, packet_buf, count, client_addr)| {
            println!("received");
            self.socket = Some(socket);
            self.packet_buf = Some(packet_buf);
            self.varz.client_queries_udp.inc();
            if count < DNS_QUERY_MIN_SIZE || count > DNS_QUERY_MAX_SIZE {
                info!("Short query using UDP");
                self.varz.client_queries_errors.inc();
                return Box::new(future::ok(self)) as Box<Future<Item = _, Error = _>>;
            }
            let normalized_question =
                match dns::normalize(&self.packet_buf.as_ref().unwrap()[..count], true) {
                    Ok(normalized_question) => normalized_question,
                    Err(e) => {
                        debug!("Error while parsing the question: {}", e);
                        self.varz.client_queries_errors.inc();
                        return Box::new(future::ok(self)) as Box<Future<Item = _, Error = _>>;
                    }
                };
            let cache_entry = self.cache.get2(&normalized_question);
            if let Some(mut cache_entry) = cache_entry {
                if !cache_entry.is_expired() {
                    self.varz.client_queries_cached.inc();
                    if cache_entry.packet.len() > normalized_question.payload_size as usize {
                        debug!("cached, but has to be truncated");
                        let packet = dns::build_tc_packet(&normalized_question).unwrap();
                        let _ = self.socket
                            .as_ref()
                            .unwrap()
                            .send_to(&packet, &client_addr);
                        return Box::new(future::ok(self)) as Box<Future<Item = _, Error = _>>;
                    }
                    debug!("cached");
                    dns::set_tid(&mut cache_entry.packet, normalized_question.tid);
                    dns::overwrite_qname(&mut cache_entry.packet, &normalized_question.qname);
                    let _ = self.socket
                        .as_ref()
                        .unwrap()
                        .send_to(&cache_entry.packet, &client_addr);
                    return Box::new(future::ok(self)) as Box<Future<Item = _, Error = _>>;
                }
                debug!("expired");
                self.varz.client_queries_expired.inc();
            }
            let client_query = ClientQuery {
                proto: ClientQueryProtocol::UDP,
                client_addr: Some(client_addr),
                tcpclient_tx: None,
                normalized_question: normalized_question,
                ts: Instant::recent(),
            };
            let client_query_fut = self.resolver_tx
                .clone()
                .send(client_query)
                .map_err(|_| io::Error::last_os_error())
                .map(|_| self);
            Box::new(client_query_fut) as Box<Future<Item = _, Error = _>>
        })
                     .and_then(move |this| Ok(Loop::Continue(this))))
    }

    fn run(mut self) -> io::Result<()> {
        debug!("udp listener socket={:?}", self.socket);
        let mut event_loop = self.event_loop.take().unwrap();
        let service_ready_tx = self.service_ready_tx.take().unwrap();
        let stream = loop_fn(self, |session| session.process());
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
