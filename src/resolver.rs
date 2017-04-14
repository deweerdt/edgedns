use cache::Cache;
use coarsetime::{Duration, Instant};
use config::Config;
use dns::{NormalizedQuestion, NormalizedQuestionKey, NormalizedQuestionMinimal,
          build_query_packet, normalize, tid, set_tid, overwrite_qname, build_tc_packet,
          build_health_check_packet, build_servfail_packet, min_ttl, set_ttl, rcode,
          DNS_HEADER_SIZE, DNS_RCODE_SERVFAIL};
use client_queries_handler::ClientQueriesHandler;
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

    pub fn record_failure(&mut self, config: &Config) {
        self.failures += 1;
        if self.failures < config.upstream_max_failures {
            return;
        }
        self.offline = true;
        warn!("Too many failures from resolver {}, putting offline",
              self.remote_addr);
    }

    pub fn live_servers(upstream_servers: &Vec<UpstreamServer>) -> Vec<usize> {
        let mut new_live: Vec<usize> = Vec::with_capacity(upstream_servers.len());
        for (idx, upstream_server) in upstream_servers.iter().enumerate() {
            if !upstream_server.offline {
                new_live.push(idx);
            }
        }
        info!("Live upstream servers: {:?}", new_live);
        new_live
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
                let stream = client_queries_handler.fut_process_stream(&handle, resolver_rx);
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
