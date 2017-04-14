use coarsetime::Instant;
use cache::Cache;
use client_query::ClientQueryProtocol;
use config::Config;
use dns::{self, NormalizedQuestion, NormalizedQuestionKey, NormalizedQuestionMinimal,
          build_query_packet};
use client_query::ClientQuery;
use futures::Future;
use futures::future;
use futures::sync::mpsc::Receiver;
use futures::sync::oneshot;
use futures::Stream;
use jumphash::JumpHasher;
use rand::distributions::{IndependentSample, Range};
use rand;
use resolver::{PendingQueries, PendingQuery, UpstreamServer, ResolverCore, LoadBalancingMode};
use std::io;
use std::net;
use std::sync::Arc;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Mutex;
use std::time;
use tokio_timer::{wheel, Timer};
use tokio_core::reactor::Handle;
use varz::Varz;

pub struct ClientQueriesHandler {
    cache: Cache,
    config: Config,
    net_udp_socket: net::UdpSocket,
    net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    pending_queries: PendingQueries,
    upstream_servers_arc: Arc<Mutex<Vec<UpstreamServer>>>,
    upstream_servers_live_arc: Arc<Mutex<Vec<usize>>>,
    waiting_clients_count: Rc<AtomicUsize>,
    jumphasher: JumpHasher,
    timer: Timer,
    varz: Arc<Varz>,
}

impl Clone for ClientQueriesHandler {
    fn clone(&self) -> Self {
        ClientQueriesHandler {
            cache: self.cache.clone(),
            config: self.config.clone(),
            net_udp_socket: self.net_udp_socket.try_clone().unwrap(),
            net_ext_udp_sockets_rc: self.net_ext_udp_sockets_rc.clone(),
            pending_queries: self.pending_queries.clone(),
            upstream_servers_arc: self.upstream_servers_arc.clone(),
            upstream_servers_live_arc: self.upstream_servers_live_arc.clone(),
            waiting_clients_count: self.waiting_clients_count.clone(),
            jumphasher: self.jumphasher,
            timer: self.timer.clone(),
            varz: self.varz.clone(),
        }
    }
}

impl ClientQueriesHandler {
    pub fn new(resolver_core: &ResolverCore) -> Self {
        let timer = wheel()
            .max_capacity(resolver_core.config.max_active_queries)
            .build();
        ClientQueriesHandler {
            cache: resolver_core.cache.clone(),
            config: resolver_core.config.clone(),
            net_udp_socket: resolver_core.net_udp_socket.try_clone().unwrap(),
            net_ext_udp_sockets_rc: resolver_core.net_ext_udp_sockets_rc.clone(),
            pending_queries: resolver_core.pending_queries.clone(),
            upstream_servers_arc: resolver_core.upstream_servers_arc.clone(),
            upstream_servers_live_arc: resolver_core.upstream_servers_live_arc.clone(),
            waiting_clients_count: resolver_core.waiting_clients_count.clone(),
            jumphasher: resolver_core.jumphasher,
            timer: timer,
            varz: resolver_core.varz.clone(),
        }
    }

    pub fn fut_process_stream(&self,
                              handle: &Handle,
                              resolver_rx: Receiver<ClientQuery>)
                              -> impl Future<Item = (), Error = io::Error> {
        let handle = handle.clone();
        let mut self_inner = self.clone();
        let fut_client_query = resolver_rx.for_each(move |client_query| {
                                                        let fut = self_inner
                                         .fut_process_client_query(client_query)
                                         .map_err(|_| {});
                                                        handle.spawn(fut);
                                                        future::ok(())
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
            let clients_count = pending_query.client_queries.len();
            let prev_count = self.waiting_clients_count
                .fetch_sub(clients_count, Relaxed);
            assert!(prev_count >= clients_count);
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
                self.waiting_clients_count.fetch_add(1, Relaxed);
                true
            }
        }
    }

    fn maybe_respond_with_stale_entry(&mut self,
                                      client_query: ClientQuery)
                                      -> Box<Future<Item = (), Error = io::Error>> {
        let normalized_question = &client_query.normalized_question;
        let cache_entry = self.cache.get2(&normalized_question);
        if let Some(mut cache_entry) = cache_entry {
            self.varz.client_queries_offline.inc();
            debug!("All upstream servers are down - Responding with stale entry");
            return client_query.response_send(&mut cache_entry.packet, &self.net_udp_socket);
        }
        Box::new(future::ok(()))
    }

    fn fut_process_client_query(&mut self,
                                client_query: ClientQuery)
                                -> Box<Future<Item = (), Error = io::Error>> {
        info!("Incoming client query {:#?}", client_query);
        if self.upstream_servers_live_arc
               .lock()
               .unwrap()
               .is_empty() {
            return self.maybe_respond_with_stale_entry(client_query);
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
        debug_assert_eq!(pending_query.client_queries.len(), 1);
        self.waiting_clients_count.fetch_add(1, Relaxed);
        let mut map = self.pending_queries.map_arc.lock().unwrap();
        debug!("Sending {:#?} to {:?}",
               pending_query.normalized_question_minimal,
               pending_query.socket_addr);
        map.insert(key, pending_query);
        let _ = net_ext_udp_socket.send_to(&query_packet, &upstream_server.socket_addr);
        upstream_server.pending_queries = upstream_server.pending_queries.wrapping_add(1);
        let done_rx = done_rx.map_err(|_| ());
        let timeout = self.timer.timeout(done_rx, time::Duration::from_secs(1));
        let retry_query = RetryQueryHandler::new(&self, &normalized_question);
        let upstream_servers_arc = self.upstream_servers_arc.clone();
        let upstream_servers_live_arc = self.upstream_servers_live_arc.clone();
        let config = self.config.clone();
        let fut = timeout
            .map(|_| {})
            .map_err(|_| io::Error::last_os_error())
            .or_else(move |_| {
                {
                    let mut upstream_servers = upstream_servers_arc.lock().unwrap();
                    upstream_servers[upstream_server_idx].record_failure(&config);
                    *upstream_servers_live_arc.lock().unwrap() =
                        UpstreamServer::live_servers(&mut upstream_servers);
                }
                retry_query.fut_retry_query()
            });
        return Box::new(fut);
    }
}

#[derive(Clone)]
pub struct RetryQueryHandler {
    config: Config,
    net_ext_udp_sockets_rc: Rc<Vec<net::UdpSocket>>,
    pending_queries: PendingQueries,
    upstream_servers_arc: Arc<Mutex<Vec<UpstreamServer>>>,
    upstream_servers_live_arc: Arc<Mutex<Vec<usize>>>,
    waiting_clients_count: Rc<AtomicUsize>,
    jumphasher: JumpHasher,
    timer: Timer,
    normalized_question: NormalizedQuestion,
}

impl RetryQueryHandler {
    fn new(client_queries_handler: &ClientQueriesHandler,
           normalized_question: &NormalizedQuestion)
           -> Self {
        RetryQueryHandler {
            config: client_queries_handler.config.clone(),
            net_ext_udp_sockets_rc: client_queries_handler.net_ext_udp_sockets_rc.clone(),
            pending_queries: client_queries_handler.pending_queries.clone(),
            upstream_servers_arc: client_queries_handler.upstream_servers_arc.clone(),
            upstream_servers_live_arc: client_queries_handler.upstream_servers_live_arc.clone(),
            waiting_clients_count: client_queries_handler.waiting_clients_count.clone(),
            jumphasher: client_queries_handler.jumphasher.clone(),
            timer: client_queries_handler.timer.clone(),
            normalized_question: normalized_question.clone(),
        }
    }

    fn fut_retry_query(&self) -> Box<Future<Item = (), Error = io::Error>> {
        info!("timeout");
        let mut map = self.pending_queries.map_arc.lock().unwrap();
        let key = self.normalized_question.key();
        let mut pending_query = match map.get_mut(&key) {
            None => return Box::new(future::ok(())) as Box<Future<Item = (), Error = io::Error>>,
            Some(pending_query) => pending_query,
        };
        let mut upstream_servers = self.upstream_servers_arc.lock().unwrap();
        let nq = self.normalized_question
            .new_pending_query(&upstream_servers,
                               &self.upstream_servers_live_arc.lock().unwrap(),
                               &self.net_ext_udp_sockets_rc,
                               &self.jumphasher,
                               true,
                               self.config.lbmode);
        let (query_packet, normalized_question_minimal, upstream_server_idx, net_ext_udp_socket) =
            match nq {
                Ok(x) => x,
                Err(_) => {
                    return Box::new(future::ok(())) as Box<Future<Item = (), Error = io::Error>>
                }
            };
        let upstream_server = &mut upstream_servers[upstream_server_idx];

        debug!("new attempt with upstream server: {:?}",
               upstream_server.socket_addr);
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
        let timeout = self.timer.timeout(done_rx, time::Duration::from_secs(2));
        let map_arc = self.pending_queries.map_arc.clone();
        let waiting_clients_count = self.waiting_clients_count.clone();
        let upstream_servers_arc = self.upstream_servers_arc.clone();
        let upstream_servers_live_arc = self.upstream_servers_live_arc.clone();
        let config = self.config.clone();
        let fut = timeout
            .map(|_| {})
            .map_err(|_| io::Error::last_os_error())
            .or_else(move |_| {
                info!("retry failed as well");
                {
                    let mut upstream_servers = upstream_servers_arc.lock().unwrap();
                    upstream_servers[upstream_server_idx].record_failure(&config);
                    *upstream_servers_live_arc.lock().unwrap() =
                        UpstreamServer::live_servers(&mut upstream_servers);
                }
                let mut map = map_arc.lock().unwrap();
                if let Some(pending_query) = map.remove(&key) {
                    let _ = pending_query.done_tx.send(());
                    waiting_clients_count.store(pending_query.client_queries.len(), Relaxed);
                }
                Box::new(future::ok(())) as Box<Future<Item = (), Error = io::Error>>
            });
        info!("retrying...");
        Box::new(fut) as Box<Future<Item = (), Error = io::Error>>
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
