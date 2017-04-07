use cache::Cache;
use coarsetime::{Duration, Instant};
use config::Config;
use dns::{NormalizedQuestion, NormalizedQuestionKey, NormalizedQuestionMinimal,
          build_query_packet, normalize, tid, set_tid, overwrite_qname, build_tc_packet,
          build_health_check_packet, build_servfail_packet, min_ttl, set_ttl, rcode,
          DNS_HEADER_SIZE, DNS_RCODE_SERVFAIL};
use client_query::{ClientQuery, ClientQueryProtocol};
use ext_response::ExtResponse;
use futures::Future;
use futures::future::{self, Loop, loop_fn, FutureResult};
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::sync::oneshot;
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
use std::time;
use udp_stream::*;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::{Core, Handle};
use tokio_timer::{wheel, Timer, TimeoutError};
use super::{EdgeDNSContext, DNS_MAX_UDP_SIZE, DNS_QUERY_MIN_SIZE, FAILURE_TTL,
            UPSTREAM_TIMEOUT_MS, UPSTREAM_INITIAL_TIMEOUT_MS};
use varz::Varz;

#[derive(Clone, Debug)]
pub struct ResolverResponse {
    pub response: Vec<u8>,
    pub dnssec: bool,
}

pub struct UpstreamServer {
    pub remote_addr: String,
    pub socket_addr: SocketAddr,
    pub pending_queries: u64,
    pub failures: u32,
    pub offline: bool,
}

impl UpstreamServer {
    pub fn new(remote_addr: &str) -> Result<UpstreamServer, &'static str> {
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

pub struct PendingQuery {
    pub normalized_question_minimal: NormalizedQuestionMinimal,
    pub socket_addr: SocketAddr,
    pub local_port: u16,
    pub client_queries: Vec<ClientQuery>,
    pub ts: Instant,
    pub delay: u64,
    pub upstream_server_idx: usize,
    pub done_tx: oneshot::Sender<()>,
}

impl PendingQuery {
    pub fn new(normalized_question_minimal: NormalizedQuestionMinimal,
               upstream_server: &UpstreamServer,
               upstream_server_idx: usize,
               net_ext_udp_socket: &net::UdpSocket,
               client_query: &ClientQuery,
               done_tx: oneshot::Sender<()>)
               -> Self {
        PendingQuery {
            normalized_question_minimal: normalized_question_minimal,
            socket_addr: upstream_server.socket_addr,
            local_port: net_ext_udp_socket.local_addr().unwrap().port(),
            client_queries: vec![client_query.clone()],
            ts: Instant::recent(),
            delay: UPSTREAM_INITIAL_TIMEOUT_MS,
            upstream_server_idx: upstream_server_idx,
            done_tx: done_tx,
        }
    }
}

#[derive(Clone)]
pub struct PendingQueries {
    pub map_arc: Arc<Mutex<HashMap<NormalizedQuestionKey, PendingQuery>>>,
}

impl PendingQueries {
    pub fn new() -> Self {
        let map_arc = Arc::new(Mutex::new(HashMap::new()));
        PendingQueries { map_arc: map_arc }
    }
}

struct ClientQueriesHandler {
    config: Config,
    net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    pending_queries: PendingQueries,
    upstream_servers_arc: Arc<Mutex<Vec<UpstreamServer>>>,
    upstream_servers_live_arc: Arc<Mutex<Vec<usize>>>,
    waiting_clients_count: Rc<AtomicUsize>,
    jumphasher: JumpHasher,
    timer: Timer,
}

impl ClientQueriesHandler {
    fn new(resolver_core: &ResolverCore) -> Self {
        let timer = wheel()
            .max_capacity(resolver_core.config.max_active_queries)
            .build();
        ClientQueriesHandler {
            config: resolver_core.config.clone(),
            net_ext_udp_sockets_rc: resolver_core.net_ext_udp_sockets_rc.clone(),
            pending_queries: resolver_core.pending_queries.clone(),
            upstream_servers_arc: resolver_core.upstream_servers_arc.clone(),
            upstream_servers_live_arc: resolver_core.upstream_servers_live_arc.clone(),
            waiting_clients_count: resolver_core.waiting_clients_count.clone(),
            jumphasher: resolver_core.jumphasher,
            timer: timer,
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

    fn cap_pending_queries(&mut self) -> bool {
        if self.waiting_clients_count.load(Relaxed) < self.config.max_waiting_clients {
            return false;
        }
        info!("Too many waiting clients, dropping the first slot");
        let mut map = self.pending_queries.map_arc.lock().unwrap();
        let key = match map.keys().next() {
            None => return false,
            Some(key) => key.clone(),
        };
        if let Some(pending_query) = map.remove(&key) {
            self.waiting_clients_count
                .fetch_sub(pending_query.client_queries.len(), Relaxed);
        }
        true
    }

    fn maybe_add_to_existing_pending_query(&mut self,
                                           normalized_question_key: &NormalizedQuestionKey,
                                           client_query: &ClientQuery)
                                           -> bool {
        let mut pending_queries = self.pending_queries.map_arc.lock().unwrap();
        match pending_queries.get_mut(&normalized_question_key) {
            None => false,
            Some(pending_query) => {
                pending_query.client_queries.push(client_query.clone());
                self.waiting_clients_count
                    .store(pending_query.client_queries.len(), Relaxed);
                true
            }
        }
    }

    fn fut_process_client_query(&mut self,
                                client_query: ClientQuery)
                                -> Box<Future<Item = (), Error = io::Error>> {
        info!("Incoming client query {:#?}", client_query);
        if self.upstream_servers_live_arc
               .lock()
               .unwrap()
               .is_empty() {
            // Respond with stale records rom cache
            return Box::new(future::ok(()));
        }
        let normalized_question = &client_query.normalized_question;
        let key = normalized_question.key();
        self.cap_pending_queries();
        if self.maybe_add_to_existing_pending_query(&key, &client_query) {
            return Box::new(future::ok(()));
        }
        let mut upstream_servers = self.upstream_servers_arc.lock().unwrap();
        let (query_packet, normalized_question_minimal, upstream_server_idx, net_ext_udp_socket) =
            match normalized_question.new_pending_query(&upstream_servers,
                                                        &self.upstream_servers_live_arc
                                                             .lock()
                                                             .unwrap(),
                                                        &self.net_ext_udp_sockets_rc,
                                                        &self.jumphasher,
                                                        false,
                                                        self.config.lbmode) {
                Err(_) => return Box::new(future::ok(())),
                Ok(res) => res,
            };
        let mut upstream_server = &mut upstream_servers[upstream_server_idx];
        let (done_tx, done_rx) = oneshot::channel();
        let pending_query = PendingQuery::new(normalized_question_minimal,
                                              upstream_server,
                                              upstream_server_idx,
                                              net_ext_udp_socket,
                                              &client_query,
                                              done_tx);
        self.waiting_clients_count
            .store(pending_query.client_queries.len(), Relaxed);
        let mut map = self.pending_queries.map_arc.lock().unwrap();
        debug!("Sending {:#?} to {:?}",
               pending_query.normalized_question_minimal,
               pending_query.socket_addr);
        map.insert(key, pending_query);
        let _ = net_ext_udp_socket.send_to(&query_packet, &upstream_server.socket_addr);
        upstream_server.pending_queries = upstream_server.pending_queries.wrapping_add(1);
        let done_rx = done_rx.map_err(|_| ());
        let timeout = self.timer.timeout(done_rx, time::Duration::from_secs(1));

        let upstream_servers_arc = self.upstream_servers_arc.clone();
        let upstream_servers_live_arc = self.upstream_servers_live_arc.clone();
        let net_ext_udp_sockets_rc = self.net_ext_udp_sockets_rc.clone();
        let lbmode = self.config.lbmode;
        let jumphasher = self.jumphasher.clone();
        let normalized_question = normalized_question.clone();
        let map_arc = self.pending_queries.map_arc.clone();
        let timer = self.timer.clone();
        let waiting_clients_count = self.waiting_clients_count.clone();

        let fut = timeout
            .map(|_| {})
            .map_err(|_| io::Error::last_os_error())
            .or_else(move |_| {
                info!("timeout");
                let mut map = map_arc.lock().unwrap();
                let key = normalized_question.key();
                let mut pending_query = match map.get_mut(&key) {
                    None => {
                        return Box::new(future::ok(())) as Box<Future<Item = (), Error = io::Error>>
                    }
                    Some(pending_query) => pending_query,
                };
                let mut upstream_servers = upstream_servers_arc.lock().unwrap();
                let nq = normalized_question.new_pending_query(&upstream_servers,
                                                               &upstream_servers_live_arc
                                                                    .lock()
                                                                    .unwrap(),
                                                               &net_ext_udp_sockets_rc,
                                                               &jumphasher,
                                                               true,
                                                               lbmode);
                let (query_packet,
                     normalized_question_minimal,
                     upstream_server_idx,
                     net_ext_udp_socket) = match nq {
                    Ok(x) => x,
                    Err(_) => {
                        return Box::new(future::ok(())) as Box<Future<Item = (), Error = io::Error>>
                    }
                };
                let upstream_server = &mut upstream_servers[upstream_server_idx];
                debug!("upstream server: {:?}", upstream_server.socket_addr);
                let (done_tx, done_rx) = oneshot::channel();
                pending_query.normalized_question_minimal = normalized_question_minimal;
                pending_query.socket_addr = upstream_server.socket_addr;
                pending_query.local_port = net_ext_udp_socket.local_addr().unwrap().port();
                pending_query.ts = Instant::recent();
                pending_query.upstream_server_idx = upstream_server_idx;
                pending_query.done_tx = done_tx;
                let _ = net_ext_udp_socket.send_to(&query_packet, &upstream_server.socket_addr);
                upstream_server.pending_queries = upstream_server.pending_queries.wrapping_add(1);
                let done_rx = done_rx.map_err(|_| ());
                let timeout = timer.timeout(done_rx, time::Duration::from_secs(1));

                let map_arc = map_arc.clone();
                let fut = timeout
                    .map(|_| {})
                    .map_err(|_| io::Error::last_os_error())
                    .or_else(move |_| {
                        info!("retry failed as well");
                        let mut map = map_arc.lock().unwrap();
                        if let Some(pending_query) = map.remove(&key) {
                            let _ = pending_query.done_tx.send(());
                            waiting_clients_count.store(pending_query.client_queries.len(),
                                                        Relaxed);
                        }
                        Box::new(future::ok(()))
                    });
                info!("retrying...");
                Box::new(fut) as Box<Future<Item = (), Error = io::Error>>
            });
        return Box::new(fut);
    }
}

pub struct ResolverCore {
    pub config: Config,
    pub dnstap_sender: Option<log_dnstap::Sender>,
    pub net_udp_socket: net::UdpSocket,
    pub net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    pub pending_queries: PendingQueries,
    pub upstream_servers_arc: Arc<Mutex<Vec<UpstreamServer>>>,
    pub upstream_servers_live_arc: Arc<Mutex<Vec<usize>>>,
    pub waiting_clients_count: Rc<AtomicUsize>,
    pub cache: Cache,
    pub varz: Arc<Varz>,
    pub decrement_ttl: bool,
    pub lbmode: LoadBalancingMode,
    pub upstream_max_failures: u32,
    pub jumphasher: JumpHasher,
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
        let upstream_servers_arc = Arc::new(Mutex::new(upstream_servers));
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
                    net_ext_udp_sockets_rc: Rc::new(net_ext_udp_sockets),
                    pending_queries: pending_queries,
                    upstream_servers_arc: upstream_servers_arc,
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
                for net_ext_udp_socket in &*resolver_core.net_ext_udp_sockets_rc {
                    let ext_response_listener =
                        ExtResponse::new(&resolver_core,
                                         net_ext_udp_socket.local_addr().unwrap().port());
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
