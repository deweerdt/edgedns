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
use std::thread;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Core;
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

struct PendingQueries {
    map: HashMap<NormalizedQuestionKey, ActiveQuery>,
}

struct ActiveQuery {
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
        let map = HashMap::new();
        PendingQueries { map: map }
    }
}

pub struct Resolver {
    config: Config,
    dnstap_sender: Option<log_dnstap::Sender>,
    net_udp_socket: net::UdpSocket,
    net_ext_udp_sockets: Vec<net::UdpSocket>,
    pending_queries: PendingQueries,
    upstream_servers: Vec<UpstreamServer>,
    upstream_servers_live: Vec<usize>,
    waiting_clients_count: usize,
    cache: Cache,
    varz: Arc<Varz>,
    decrement_ttl: bool,
    lbmode: LoadBalancingMode,
    upstream_max_failures: u32,
    jumphasher: JumpHasher,
}

impl Resolver {
    fn verify_active_query(active_query: &ActiveQuery,
                           packet: &[u8],
                           client_addr: SocketAddr,
                           local_port: u16)
                           -> Result<(), &'static str> {
        if local_port != active_query.local_port {
            debug!("Got a reponse on port {} for a query sent on port {}",
                   local_port,
                   active_query.local_port);
            return Err("Response on an unexpected port");
        }
        if active_query.socket_addr != client_addr {
            info!("Sent a query to {:?} but got a response from {:?}",
                  active_query.socket_addr,
                  client_addr);
            return Err("Response from an unexpected peer");
        }
        if active_query.normalized_question_minimal.tid != tid(packet) {
            debug!("Sent a query with tid {} but got a response for tid {:?}",
                   active_query.normalized_question_minimal.tid,
                   tid(packet));
            return Err("Response with an unexpected tid");
        }
        Ok(())
    }

    fn dispatch_active_query(resolver: &RefMut<Self>,
                             packet: &mut [u8],
                             normalized_question_key: &NormalizedQuestionKey,
                             client_addr: SocketAddr,
                             local_port: u16) {
        let active_query = match resolver
                  .pending_queries
                  .map
                  .get(normalized_question_key) {
            None => {
                debug!("No clients waiting for this query");
                return;
            }
            Some(active_query) => active_query,
        };
        if Self::verify_active_query(active_query, packet, client_addr, local_port).is_err() {
            debug!("Received response is not valid for the query originally sent");
            return;
        }
        if let Some(ref dnstap_sender) = resolver.dnstap_sender {
            dnstap_sender.send_forwarder_response(packet, client_addr, local_port);
        }
        let client_queries = &active_query.client_queries;
        for client_query in client_queries {
            set_tid(packet, client_query.normalized_question.tid);
            overwrite_qname(packet, &client_query.normalized_question.qname);
            resolver.varz.upstream_received.inc();
            match client_query.proto {
                ClientQueryProtocol::UDP => {
                    if client_query.ts.elapsed_since_recent() <
                       Duration::from_millis(UPSTREAM_TIMEOUT_MS) {
                        if packet.len() > client_query.normalized_question.payload_size as usize {
                            let packet = &build_tc_packet(&client_query.normalized_question)
                                              .unwrap();
                            let _ = resolver
                                .net_udp_socket
                                .send_to(packet, client_query.client_addr.unwrap());
                        } else {
                            let _ = resolver
                                .net_udp_socket
                                .send_to(packet, client_query.client_addr.unwrap());
                        }
                    }
                }
                ClientQueryProtocol::TCP => {
                    let resolver_response = ResolverResponse {
                        response: packet.to_vec(),
                        dnssec: client_query.normalized_question.dnssec,
                    };
                    // XXX - TODO
                }
            }
        }
    }

    fn complete_active_query(resolver: &mut RefMut<Self>,
                             packet: &mut [u8],
                             normalized_question: NormalizedQuestion,
                             client_addr: SocketAddr,
                             local_port: u16,
                             ttl: u32) {
        let normalized_question_key = normalized_question.key();
        Self::dispatch_active_query(resolver,
                                    packet,
                                    &normalized_question_key,
                                    client_addr,
                                    local_port);
        if let Some(active_query) =
            resolver
                .pending_queries
                .map
                .remove(&normalized_question_key) {
            resolver.waiting_clients_count -= active_query.client_queries.len();
        }
        if rcode(packet) == DNS_RCODE_SERVFAIL {
            match resolver.cache.get(&normalized_question_key) {
                None => {
                    resolver
                        .cache
                        .insert(normalized_question_key, packet.to_owned(), FAILURE_TTL);
                }
                Some(cache_entry) => {
                    resolver
                        .cache
                        .insert(normalized_question_key, cache_entry.packet, FAILURE_TTL);
                    resolver.varz.client_queries_offline.inc();
                }
            }
        } else {
            resolver
                .cache
                .insert(normalized_question_key, packet.to_owned(), ttl);
        }
    }

    fn update_cache_stats(resolver: &RefMut<Self>) {
        let cache_stats = resolver.cache.stats();
        resolver
            .varz
            .cache_frequent_len
            .set(cache_stats.frequent_len as f64);
        resolver
            .varz
            .cache_recent_len
            .set(cache_stats.recent_len as f64);
        resolver
            .varz
            .cache_test_len
            .set(cache_stats.test_len as f64);
        resolver
            .varz
            .cache_inserted
            .set(cache_stats.inserted as f64);
        resolver
            .varz
            .cache_evicted
            .set(cache_stats.evicted as f64);
    }

    fn handle_upstream_response(mut resolver: &mut RefMut<Self>,
                                packet: &mut [u8],
                                client_addr: SocketAddr,
                                local_port: u16) {
        if packet.len() < DNS_QUERY_MIN_SIZE {
            info!("Short response without a query, using UDP");
            resolver.varz.upstream_errors.inc();
            return;
        }
        let normalized_question = match normalize(packet, false) {
            Err(e) => {
                info!("Unexpected question in a response: {}", e);
                return;
            }
            Ok(normalized_question) => normalized_question,
        };
        let ttl = match min_ttl(packet,
                                resolver.config.min_ttl,
                                resolver.config.max_ttl,
                                FAILURE_TTL) {
            Err(e) => {
                info!("Unexpected answers in a response ({}): {}",
                      normalized_question,
                      e);
                resolver.varz.upstream_errors.inc();
                return;
            }
            Ok(ttl) => {
                if rcode(packet) == DNS_RCODE_SERVFAIL {
                    let _ = set_ttl(packet, FAILURE_TTL);
                    FAILURE_TTL
                } else if ttl < resolver.config.min_ttl {
                    if resolver.decrement_ttl {
                        let _ = set_ttl(packet, resolver.config.min_ttl);
                    }
                    resolver.config.min_ttl
                } else {
                    ttl
                }
            }
        };
        Self::complete_active_query(&mut resolver,
                                    packet,
                                    normalized_question,
                                    client_addr,
                                    local_port,
                                    ttl);
        Self::update_cache_stats(&resolver);
    }

    fn fut_ext_udp_socket
        (ext_udp_socket: UdpSocket,
         resolver_rc: Rc<RefCell<Resolver>>)
         -> impl Future<Item = (UdpSocket, Rc<RefCell<Resolver>>), Error = io::Error> {
        let fut_ext_socket = ext_udp_socket.recv_dgram(vec![0u8; DNS_MAX_UDP_SIZE]);
        let stream = fut_ext_socket.and_then(|(ext_udp_socket, mut packet, count, client_addr)| {
            if count < DNS_HEADER_SIZE {
                info!("Short response without a header, using UDP");
                resolver_rc.borrow().varz.upstream_errors.inc();
                return future::ok((ext_udp_socket, resolver_rc));
            }
            {
                let mut resolver = resolver_rc.borrow_mut();
                if let Some(idx) =
                    resolver
                        .upstream_servers
                        .iter()
                        .position(|upstream_server| upstream_server.socket_addr == client_addr) {
                    if !resolver.upstream_servers_live.iter().any(|&x| x == idx) {
                        resolver.upstream_servers[idx].pending_queries = 0;
                        resolver.upstream_servers[idx].failures = 0;
                        resolver.upstream_servers[idx].offline = false;
                        resolver.upstream_servers_live.push(idx);
                        resolver.upstream_servers_live.sort();
                        info!("{} came back online",
                              resolver.upstream_servers[idx].remote_addr);
                    } else {
                        if resolver.upstream_servers[idx].pending_queries > 0 {
                            resolver.upstream_servers[idx].pending_queries -= 1;
                        }
                        if resolver.upstream_servers[idx].failures > 0 {
                            resolver.upstream_servers[idx].failures -= 1;
                            debug!("Failures count for server {} decreased to {}",
                                   idx,
                                   resolver.upstream_servers[idx].failures);
                        }
                    }
                }
                let packet = &mut packet[..count];
                let local_port = ext_udp_socket
                    .local_addr()
                    .expect("Can't get the local address for an external UDP listener")
                    .port();
                Self::handle_upstream_response(&mut resolver, packet, client_addr, local_port);
            }
            future::ok((ext_udp_socket, resolver_rc))
        });
        stream
    }

    fn respond_from_cache(mut resolver: &mut RefMut<Self>,
                          client_query: &ClientQuery)
                          -> Result<(), &'static str> {
        let normalized_question = &client_query.normalized_question;
        let normalized_question_key = normalized_question.key();
        let cache_entry = resolver.cache.get(&normalized_question_key);
        let mut packet = if let Some(cache_entry) = cache_entry {
            cache_entry.packet.clone()
        } else {
            return Err("Response is not present in cache");
        };
        debug!("Responding from cache");
        resolver.varz.client_queries_offline.inc();
        overwrite_qname(&mut packet, &client_query.normalized_question.qname);
        set_tid(&mut packet, client_query.normalized_question.tid);
        match client_query.proto {
            ClientQueryProtocol::UDP => {
                if client_query.ts.elapsed_since_recent() <
                   Duration::from_millis(UPSTREAM_TIMEOUT_MS) {
                    if packet.len() > client_query.normalized_question.payload_size as usize {
                        let packet = build_tc_packet(&client_query.normalized_question).unwrap();
                        let _ = resolver
                            .net_udp_socket
                            .send_to(&packet, client_query.client_addr.unwrap());
                    } else {
                        let _ = resolver
                            .net_udp_socket
                            .send_to(&packet, client_query.client_addr.unwrap());
                    };
                }
            }
            ClientQueryProtocol::TCP => {
                let resolver_response = ResolverResponse {
                    response: packet.to_vec(),
                    dnssec: client_query.normalized_question.dnssec,
                };
                let tcpclient_tx = client_query.tcpclient_tx.clone().unwrap();
                // XXX - TODO
            }
        }
        Ok(())
    }

    fn fut_client_query(resolver_rc: Rc<RefCell<Resolver>>,
                        client_query: ClientQuery)
                        -> impl Future<Item = (), Error = ()> {
        let key = {
            let mut resolver = resolver_rc.borrow_mut();
            if resolver.upstream_servers_live.is_empty() {
                if Self::respond_from_cache(&mut resolver, &client_query).is_ok() {
                    return future::ok(());
                }
            }
            let normalized_question = &client_query.normalized_question;
            let key = normalized_question.key();
            if resolver.waiting_clients_count > resolver.config.max_waiting_clients {
                info!("Too many waiting clients, dropping the first slot");
                let key = match resolver.pending_queries.map.keys().next() {
                    None => return future::ok((())),
                    Some(key) => key.clone(),
                };
                if let Some(active_query) = resolver.pending_queries.map.remove(&key) {
                    resolver.waiting_clients_count -= active_query.client_queries.len();
                    // XXX - Cancel timeout?
                }
                return future::ok((()));
            }
            key
        };
        let mut create_active_query = true;
        if let Some(active_query) =
            resolver_rc
                .borrow_mut()
                .pending_queries
                .map
                .get_mut(&key) {
            let resolver = resolver_rc.borrow();
            create_active_query = false;
            if active_query.client_queries.len() < resolver.config.max_clients_waiting_for_query {
                active_query.client_queries.push(client_query.clone());
                resolver_rc.borrow_mut().waiting_clients_count += 1;
            } else {
                info!("More than {} clients waiting for a response to the same query",
                      resolver.config.max_clients_waiting_for_query);
            }
        }
        future::ok((()))
    }

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
        let resolver = Resolver {
            config: edgedns_context.config.clone(),
            dnstap_sender: edgedns_context.dnstap_sender.clone(),
            net_udp_socket: net_udp_socket,
            net_ext_udp_sockets: net_ext_udp_sockets,
            pending_queries: pending_queries,
            upstream_servers: upstream_servers,
            upstream_servers_live: upstream_servers_live,
            waiting_clients_count: 0,
            cache: edgedns_context.cache.clone(),
            varz: edgedns_context.varz.clone(),
            decrement_ttl: config.decrement_ttl,
            lbmode: config.lbmode,
            upstream_max_failures: config.upstream_max_failures,
            jumphasher: JumpHasher::default(),
        };
        if config.decrement_ttl {
            info!("Resolver mode: TTL will be automatically decremented");
        }
        thread::Builder::new()
            .name("resolver".to_string())
            .spawn(move || {
                let resolver_rc = Rc::new(RefCell::new(resolver));
                let mut event_loop = Core::new().expect("No event loop");
                let handle = event_loop.handle();
                info!("Registering UDP ports...");
                for net_ext_udp_socket in &resolver_rc.borrow().net_ext_udp_sockets {
                    let ext_udp_socket =
                        UdpSocket::from_socket(net_ext_udp_socket.try_clone().unwrap(), &handle)
                            .expect("Cannot create an external tokio socket from a raw socket");
                    let stream = loop_fn::<_,
                                           (UdpSocket, Rc<RefCell<Resolver>>),
                                           _,
                                           _>((ext_udp_socket, resolver_rc.clone()),
                                              move |(ext_udp_socket, resolver_rc)| {
                        Self::fut_ext_udp_socket(ext_udp_socket, resolver_rc)                        
                            .map_err(|_| {})
                            .and_then(|(ext_udp_socket, resolver_rc)| {
                                          Ok(Loop::Continue((ext_udp_socket, resolver_rc)))
                                      })
                    });
                    handle.spawn(stream.map_err(|_| {}).map(|_| {}));
                }                
                let stream = resolver_rx.for_each(move |client_query| {
                    Self::fut_client_query(resolver_rc.clone(), client_query)
                });
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

    fn new_active_query<'t>
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
