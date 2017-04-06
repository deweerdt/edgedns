use cache::Cache;
use coarsetime::{Duration, Instant};
use config::Config;
use dns::{NormalizedQuestion, NormalizedQuestionKey, NormalizedQuestionMinimal,
          build_query_packet, normalize, tid, set_tid, overwrite_qname, build_tc_packet,
          build_health_check_packet, build_servfail_packet, min_ttl, set_ttl, rcode,
          DNS_HEADER_SIZE, DNS_RCODE_SERVFAIL};
use client_query::{ClientQuery, ClientQueryProtocol};
use futures::Future;
use futures::future::{self, Loop, loop_fn, FutureResult};
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::Stream;
use jumphash::JumpHasher;
use log_dnstap;
use net_helpers::*;
use nix::sys::socket::{bind, setsockopt, sockopt, SockAddr, InetAddr};
use rand::distributions::{IndependentSample, Range};
use rand;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::FromRawFd;
use std::collections::HashMap;
use std::io;
use std::net;
use std::sync::Arc;
use std::cell::{RefCell, RefMut};
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Mutex;
use std::thread;
use udp_stream::*;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::{Core, Handle};
use super::{EdgeDNSContext, DNS_MAX_UDP_SIZE, DNS_QUERY_MIN_SIZE, FAILURE_TTL, UPSTREAM_TIMEOUT_MS};
use varz::Varz;

#[derive(Clone, Debug)]
pub struct ResolverResponse {
    pub response: Vec<u8>,
    pub dnssec: bool,
}

struct UpstreamServer {
    remote_addr: String,
    socket_addr: SocketAddr,
    pending_queries: u64,
    failures: u32,
    offline: bool,
}

impl UpstreamServer {
    fn new(remote_addr: &str) -> Result<UpstreamServer, &'static str> {
        let socket_addr = match remote_addr.parse() {
            Err(_) => return Err("Unable to parse an upstream resolver address"),
            Ok(socket_addr) => socket_addr,
        };
        let upstream_server = UpstreamServer {
            remote_addr: remote_addr.to_owned(),
            socket_addr: socket_addr,
            pending_queries: 0,
            failures: 0,
            offline: false,
        };
        Ok(upstream_server)
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LoadBalancingMode {
    Uniform,
    Fallback,
    P2,
}

#[derive(Clone)]
struct PendingQueries {
    map_arc: Arc<Mutex<HashMap<NormalizedQuestionKey, PendingQuery>>>,
}

struct PendingQuery {
    normalized_question_minimal: NormalizedQuestionMinimal,
    socket_addr: SocketAddr,
    local_port: u16,
    client_queries: Vec<ClientQuery>,
    ts: Instant,
    delay: u64,
    upstream_server_idx: usize,
}

impl PendingQueries {
    fn new() -> PendingQueries {
        let map_arc = Arc::new(Mutex::new(HashMap::new()));
        PendingQueries { map_arc: map_arc }
    }
}

pub struct ExtResponse {
    config: Config,
    dnstap_sender: Option<log_dnstap::Sender>,
    pending_queries: PendingQueries,
    cache: Cache,
    varz: Arc<Varz>,
    decrement_ttl: bool,
}

impl ExtResponse {
    fn new(resolver_core: &ResolverCore) -> Self {
        ExtResponse {
            config: resolver_core.config.clone(),
            dnstap_sender: resolver_core.dnstap_sender.clone(),
            pending_queries: resolver_core.pending_queries.clone(),
            cache: resolver_core.cache.clone(),
            varz: resolver_core.varz.clone(),
            decrement_ttl: resolver_core.decrement_ttl,
        }
    }

    fn fut_process_stream<'a>(mut self,
                              handle: &Handle,
                              net_ext_udp_socket: &net::UdpSocket)
                              -> impl Future<Item = (), Error = io::Error> + 'a {
        let fut_ext_socket =
            UdpStream::from_net_udp_socket(net_ext_udp_socket
                                               .try_clone()
                                               .expect("Cannot clone a UDP socket"),
                                           &handle)
                    .expect("Cannot create a UDP stream")
                    .for_each(move |(packet, client_addr)| {
                                  self.fut_process_ext_socket(packet, client_addr)
                              })
                    .map_err(|_| io::Error::last_os_error());
        fut_ext_socket
    }

    fn fut_process_ext_socket(&mut self,
                              packet: Rc<Vec<u8>>,
                              client_addr: SocketAddr)
                              -> Box<Future<Item = (), Error = io::Error>> {
        println!("received on an external socket {:?}", packet);
        Box::new(future::ok((())))
    }
}

struct ClientQueriesHandler {
    config: Config,
    pending_queries: PendingQueries,
    upstream_servers_live_arc: Arc<Mutex<Vec<usize>>>,
    waiting_clients_count: Rc<AtomicUsize>,
}

impl ClientQueriesHandler {
    fn new(resolver_core: &ResolverCore) -> Self {
        ClientQueriesHandler {
            config: resolver_core.config.clone(),
            pending_queries: resolver_core.pending_queries.clone(),
            upstream_servers_live_arc: resolver_core.upstream_servers_live_arc.clone(),
            waiting_clients_count: resolver_core.waiting_clients_count.clone(),
        }
    }

    fn fut_process_stream<'a>(mut self,
                              resolver_rx: Receiver<ClientQuery>)
                              -> impl Future<Item = (), Error = io::Error> + 'a {
        let fut_client_query = resolver_rx.for_each(move |client_query| {
                                                        self.fut_process_client_query(client_query)
                                                            .map_err(|_| {})
                                                    });
        fut_client_query.map_err(|_| io::Error::last_os_error())
    }

    fn fut_process_client_query(&mut self,
                                client_query: ClientQuery)
                                -> Box<Future<Item = (), Error = io::Error>> {
        info!("Incoming client query {:#?}", client_query);
        if self.upstream_servers_live_arc
               .lock()
               .unwrap()
               .is_empty() {
            // Respond from cache
            return Box::new(future::ok(()));
        }
        let normalized_question = &client_query.normalized_question;
        let key = normalized_question.key();
        if self.waiting_clients_count.load(Relaxed) > self.config.max_waiting_clients {
            info!("Too many waiting clients, dropping the first slot");
            let mut map = self.pending_queries.map_arc.lock().unwrap();
            let key = match map.keys().next() {
                None => return Box::new(future::ok((()))),
                Some(key) => key.clone(),
            };
            if let Some(pending_query) = map.remove(&key) {
                self.waiting_clients_count
                    .fetch_sub(pending_query.client_queries.len(), Relaxed);
            }
        }
        if let Some(pending_query) =
            self.pending_queries
                .map_arc
                .lock()
                .unwrap()
                .get_mut(&key) {
            //
        }
        Box::new(future::ok(()))
    }
}

pub struct ResolverCore {
    config: Config,
    dnstap_sender: Option<log_dnstap::Sender>,
    net_udp_socket: net::UdpSocket,
    net_ext_udp_sockets: Vec<net::UdpSocket>,
    pending_queries: PendingQueries,
    upstream_servers: Vec<UpstreamServer>,
    upstream_servers_live_arc: Arc<Mutex<Vec<usize>>>,
    waiting_clients_count: Rc<AtomicUsize>,
    cache: Cache,
    varz: Arc<Varz>,
    decrement_ttl: bool,
    lbmode: LoadBalancingMode,
    upstream_max_failures: u32,
    jumphasher: JumpHasher,
}

impl ResolverCore {
    pub fn spawn(edgedns_context: &EdgeDNSContext) -> io::Result<Sender<ClientQuery>> {
        let config = &edgedns_context.config;
        let net_udp_socket = edgedns_context
            .udp_socket
            .try_clone()
            .expect("Unable to clone the UDP listening socket");
        let (resolver_tx, resolver_rx): (Sender<ClientQuery>, Receiver<ClientQuery>) =
            channel(edgedns_context.config.max_active_queries);
        let pending_queries = PendingQueries::new();
        let mut net_ext_udp_sockets: Vec<net::UdpSocket> = Vec::new();
        let ports = if config.udp_ports > 65535 - 1024 {
            65535 - 1024
        } else {
            config.udp_ports
        };
        for port in 1024..1024 + ports {
            if (port + 1) % 1024 == 0 {
                info!("Binding ports... {}/{}", port, ports)
            }
            if let Ok(net_ext_udp_socket) = net_socket_udp_bound(port) {
                net_ext_udp_sockets.push(net_ext_udp_socket);
            }
        }
        if net_ext_udp_sockets.is_empty() {
            panic!("Couldn't bind any ports");
        }
        let upstream_servers: Vec<UpstreamServer> = config
            .upstream_servers
            .iter()
            .map(|s| UpstreamServer::new(s).expect("Invalid upstream server address"))
            .collect();
        let upstream_servers_live: Vec<usize> = (0..config.upstream_servers.len()).collect();
        let upstream_servers_live_arc = Arc::new(Mutex::new(upstream_servers_live));
        if config.decrement_ttl {
            info!("Resolver mode: TTL will be automatically decremented");
        }
        let config = edgedns_context.config.clone();
        let dnstap_sender = edgedns_context.dnstap_sender.clone();
        let cache = edgedns_context.cache.clone();
        let varz = edgedns_context.varz.clone();
        let decrement_ttl = config.decrement_ttl;
        let lbmode = config.lbmode;
        let upstream_max_failures = config.upstream_max_failures;
        thread::Builder::new()
            .name("resolver".to_string())
            .spawn(move || {
                let mut event_loop = Core::new().expect("No event loop");
                let resolver_core = ResolverCore {
                    config: config,
                    dnstap_sender: dnstap_sender,
                    net_udp_socket: net_udp_socket,
                    net_ext_udp_sockets: net_ext_udp_sockets,
                    pending_queries: pending_queries,
                    upstream_servers: upstream_servers,
                    upstream_servers_live_arc: upstream_servers_live_arc,
                    waiting_clients_count: Rc::new(AtomicUsize::new(0)),
                    cache: cache,
                    varz: varz,
                    decrement_ttl: decrement_ttl,
                    lbmode: lbmode,
                    upstream_max_failures: upstream_max_failures,
                    jumphasher: JumpHasher::default(),
                };
                let handle = event_loop.handle();
                info!("Registering UDP ports...");
                for net_ext_udp_socket in &resolver_core.net_ext_udp_sockets {
                    let ext_response_listener = ExtResponse::new(&resolver_core);
                    let stream =
                        ext_response_listener.fut_process_stream(&handle, net_ext_udp_socket);
                    handle.spawn(stream.map_err(|_| {}).map(|_| {}));
                }
                let client_queries_handler = ClientQueriesHandler::new(&resolver_core);
                let stream = client_queries_handler.fut_process_stream(resolver_rx);
                event_loop
                    .handle()
                    .spawn(stream.map_err(|_| {}).map(|_| {}));
                info!("UDP ports registered");
                loop {
                    event_loop.turn(None)
                }
            })
            .unwrap();
        Ok(resolver_tx)
    }
}

impl NormalizedQuestion {
    fn pick_upstream(&self,
                     upstream_servers: &Vec<UpstreamServer>,
                     upstream_servers_live: &Vec<usize>,
                     jumphasher: &JumpHasher,
                     is_retry: bool,
                     lbmode: LoadBalancingMode)
                     -> Result<usize, &'static str> {
        let live_count = upstream_servers_live.len();
        if live_count == 0 {
            debug!("All upstream servers are down");
            return Err("All upstream servers are down");
        }
        match lbmode {
            LoadBalancingMode::Fallback => Ok(upstream_servers_live[0]),
            LoadBalancingMode::Uniform => {
                let mut i = jumphasher.slot(&self.qname, live_count as u32) as usize;
                if is_retry {
                    i = (i + 1) % live_count;
                }
                Ok(upstream_servers_live[i])
            }
            LoadBalancingMode::P2 => {
                let mut busy_map = upstream_servers_live
                    .iter()
                    .map(|&i| (i, upstream_servers[i].pending_queries))
                    .collect::<Vec<(usize, u64)>>();
                busy_map.sort_by_key(|x| x.1);
                let i = if busy_map.len() == 1 {
                    0
                } else {
                    ((self.tid as usize) + (is_retry as usize & 1)) & 1
                };
                Ok(busy_map[i].0)
            }
        }
    }

    fn new_pending_query<'t>
        (&self,
         upstream_servers: &Vec<UpstreamServer>,
         upstream_servers_live: &Vec<usize>,
         net_ext_udp_sockets: &'t Vec<net::UdpSocket>,
         jumphasher: &JumpHasher,
         is_retry: bool,
         lbmode: LoadBalancingMode)
         -> Result<(Vec<u8>, NormalizedQuestionMinimal, usize, &'t net::UdpSocket), &'static str> {
        let (query_packet, normalized_question_minimal) =
            build_query_packet(self, false).expect("Unable to build a new query packet");
        let upstream_server_idx = match self.pick_upstream(upstream_servers,
                                                           upstream_servers_live,
                                                           jumphasher,
                                                           is_retry,
                                                           lbmode) {
            Err(e) => return Err(e),
            Ok(upstream_server_idx) => upstream_server_idx,
        };
        let mut rng = rand::thread_rng();
        let random_token_range = Range::new(0usize, net_ext_udp_sockets.len());
        let random_token = random_token_range.ind_sample(&mut rng);
        let net_ext_udp_socket = &net_ext_udp_sockets[random_token];
        Ok((query_packet, normalized_question_minimal, upstream_server_idx, net_ext_udp_socket))
    }
}

fn net_socket_udp_bound(port: u16) -> io::Result<net::UdpSocket> {
    let actual = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
    let nix_addr = SockAddr::Inet(InetAddr::from_std(&actual));
    let socket_fd = match actual {
        SocketAddr::V4(_) => try!(socket_udp_v4()),
        SocketAddr::V6(_) => try!(socket_udp_v6()),
    };
    try!(set_nonblock(socket_fd));
    try!(setsockopt(socket_fd, sockopt::ReuseAddr, &true));
    try!(setsockopt(socket_fd, sockopt::ReusePort, &true));
    socket_udp_set_buffer_size(socket_fd);
    try!(bind(socket_fd, &nix_addr));
    let net_socket: net::UdpSocket = unsafe { net::UdpSocket::from_raw_fd(socket_fd) };
    Ok(net_socket)
}

