use cache::Cache;
use coarsetime::{Duration, Instant};
use config::Config;
use dns::{NormalizedQuestion, NormalizedQuestionKey, NormalizedQuestionMinimal,
          build_query_packet, normalize, tid, set_tid, overwrite_qname, build_tc_packet,
          build_health_check_packet, build_servfail_packet, min_ttl, set_ttl, rcode,
          DNS_HEADER_SIZE, DNS_RCODE_SERVFAIL};
use client_query::ClientQuery;
use futures::Future;
use futures::future::{self, Loop, loop_fn, FutureResult};
use futures::sync::mpsc::{channel, Receiver, Sender};
use futures::Stream;
use jumphash::JumpHasher;
use log_dnstap;
use net_helpers::*;
use nix::sys::socket::{bind, setsockopt, sockopt, SockAddr, InetAddr};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::FromRawFd;
use std::collections::HashMap;
use std::io;
use std::net;
use std::sync::Arc;
use std::cell::RefCell;
use std::rc::Rc;
use std::thread;
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Core;
use super::{EdgeDNSContext, DNS_MAX_UDP_SIZE};
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
    udp_socket: net::UdpSocket,
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
    pub fn spawn(edgedns_context: &EdgeDNSContext) -> io::Result<Sender<ClientQuery>> {
        let config = &edgedns_context.config;
        let udp_socket = edgedns_context
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
            udp_socket: udp_socket,
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
                        fut_ext_udp_socket(ext_udp_socket, resolver_rc)                        
                            .map_err(|_| {})
                            .and_then(|(ext_udp_socket, resolver_rc)| {
                                          Ok(Loop::Continue((ext_udp_socket, resolver_rc)))
                                      })
                    });
                    handle.spawn(stream.map_err(|_| {}).map(|_| {}));
                }
                let stream = resolver_rx.for_each(|x| {
                                                      println!("** message received: {:#?}", x);
                                                      Ok(())
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

fn fut_ext_udp_socket
    (
    ext_udp_socket: UdpSocket,
    resolver_rc: Rc<RefCell<Resolver>>,
) -> impl Future<Item = (UdpSocket, Rc<RefCell<Resolver>>), Error = io::Error> {
    let fut_ext_socket = ext_udp_socket.recv_dgram(vec![0u8; DNS_MAX_UDP_SIZE]);
    let stream = fut_ext_socket.and_then(|(ext_udp_socket, packet, _, _)| {
                                             {
                                                 let mut resolver = resolver_rc.borrow_mut();
                                                 resolver.waiting_clients_count += 1;
                                             }
                                             future::ok((ext_udp_socket, resolver_rc))
                                         });
    stream
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