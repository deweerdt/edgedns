use cache::Cache;
use client_query::*;
use coarsetime::Instant;
use dns;
use futures::future::{self, Future};
use futures::stream::Stream;
use futures::sync::mpsc::Sender;
use futures::Sink;
use std::io;
use std::net::{self, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use super::EdgeDNSContext;
use tokio_core::reactor::{Core, Handle};
use udp_stream::*;
use varz::Varz;

use super::{DNS_QUERY_MIN_SIZE, DNS_QUERY_MAX_SIZE};

struct UdpListener {
    net_udp_socket: net::UdpSocket,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Arc<Varz>,
}

pub struct UdpListenerCore {
    net_udp_socket: net::UdpSocket,
    resolver_tx: Sender<ClientQuery>,
    cache: Cache,
    varz: Arc<Varz>,
    service_ready_tx: Option<mpsc::SyncSender<u8>>,
}

impl UdpListener {
    fn new(udp_listener_core: &UdpListenerCore) -> Self {
        UdpListener {
            net_udp_socket: udp_listener_core
                .net_udp_socket
                .try_clone()
                .expect("Couldn't clone a UDP socket"),
            resolver_tx: udp_listener_core.resolver_tx.clone(),
            cache: udp_listener_core.cache.clone(),
            varz: udp_listener_core.varz.clone(),
        }
    }

    fn fut_process_query(&mut self,
                         packet: Rc<Vec<u8>>,
                         client_addr: SocketAddr)
                         -> Box<Future<Item = (), Error = io::Error>> {
        let count = packet.len();
        if count < DNS_QUERY_MIN_SIZE || count > DNS_QUERY_MAX_SIZE {
            info!("Short query using UDP");
            self.varz.client_queries_errors.inc();
            return Box::new(future::ok(())) as Box<Future<Item = _, Error = _>>;
        }
        let normalized_question = match dns::normalize(&packet, true) {
            Ok(normalized_question) => normalized_question,
            Err(e) => {
                debug!("Error while parsing the question: {}", e);
                self.varz.client_queries_errors.inc();
                return Box::new(future::ok(())) as Box<Future<Item = _, Error = _>>;
            }
        };
        let cache_entry = self.cache.get2(&normalized_question);
        let client_query = ClientQuery::udp(client_addr, normalized_question);
        if let Some(mut cache_entry) = cache_entry {
            if !cache_entry.is_expired() {
                self.varz.client_queries_cached.inc();
                return client_query.response_send(&mut cache_entry.packet, &self.net_udp_socket);
            }
            debug!("expired");
            self.varz.client_queries_expired.inc();
        }
        debug!("Sending query to the resolver");
        let fut_resolver_query = self.resolver_tx
            .clone()
            .send(client_query)
            .map_err(|_| io::Error::last_os_error())
            .map(move |_| {});
        Box::new(fut_resolver_query) as Box<Future<Item = _, Error = _>>
    }

    fn fut_process_stream<'a>(mut self,
                              handle: &Handle)
                              -> impl Future<Item = (), Error = io::Error> + 'a {
        UdpStream::from_net_udp_socket(self.net_udp_socket
                                           .try_clone()
                                           .expect("Unable to clone UDP socket"),
                                       handle)
                .expect("Cannot create a UDP stream")
                .for_each(move |(packet, client_addr)| self.fut_process_query(packet, client_addr))
                .map_err(|_| io::Error::last_os_error())
    }
}

impl UdpListenerCore {
    fn run(mut self, mut event_loop: Core, udp_listener: UdpListener) -> io::Result<()> {
        let service_ready_tx = self.service_ready_tx.take().unwrap();
        let handle = event_loop.handle();
        let stream = udp_listener.fut_process_stream(&handle);
        handle.spawn(stream.map_err(|_| {}).map(|_| {}));
        service_ready_tx
            .send(0)
            .map_err(|_| io::Error::last_os_error())?;
        loop {
            event_loop.turn(None)
        }
    }

    pub fn spawn(edgedns_context: &EdgeDNSContext,
                 resolver_tx: Sender<ClientQuery>,
                 service_ready_tx: mpsc::SyncSender<u8>)
                 -> io::Result<(thread::JoinHandle<()>)> {
        let net_udp_socket = edgedns_context.udp_socket.try_clone()?;
        let cache = edgedns_context.cache.clone();
        let varz = edgedns_context.varz.clone();

        let udp_listener_th = thread::Builder::new()
            .name("udp_listener".to_string())
            .spawn(move || {
                let event_loop = Core::new().unwrap();
                let udp_listener_core = UdpListenerCore {
                    net_udp_socket: net_udp_socket,
                    cache: cache,
                    resolver_tx: resolver_tx,
                    service_ready_tx: Some(service_ready_tx),
                    varz: varz,
                };
                let udp_listener = UdpListener::new(&udp_listener_core);
                udp_listener_core
                    .run(event_loop, udp_listener)
                    .expect("Unable to spawn a UDP listener");
            })
            .unwrap();
        info!("UDP listener is ready");
        Ok(udp_listener_th)
    }
}
