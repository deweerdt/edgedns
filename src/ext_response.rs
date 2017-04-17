use cache::Cache;
use config::Config;
use dns::{NormalizedQuestionKey, normalize, tid, min_ttl, set_ttl, rcode, DNS_RCODE_SERVFAIL};
use client_query::ClientQuery;
use futures::Future;
use futures::future;
use futures::Stream;
use log_dnstap;
use resolver::{PendingQuery, PendingQueries, ResolverCore};
use std::io;
use std::net::{self, SocketAddr};
use std::sync::Arc;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Mutex;
use udp_stream::*;
use tokio_core::reactor::Handle;
use super::{DNS_QUERY_MIN_SIZE, FAILURE_TTL};
use upstream_server::UpstreamServer;
use varz::Varz;

pub struct ExtResponse {
    config: Rc<Config>,
    dnstap_sender: Option<log_dnstap::Sender>,
    pending_queries: PendingQueries,
    waiting_clients_count: Rc<AtomicUsize>,
    upstream_servers_arc: Arc<Mutex<Vec<UpstreamServer>>>,
    cache: Cache,
    varz: Arc<Varz>,
    decrement_ttl: bool,
    local_port: u16,
    net_udp_socket: net::UdpSocket,
}

impl ExtResponse {
    pub fn new(resolver_core: &ResolverCore, local_port: u16) -> Self {
        ExtResponse {
            config: resolver_core.config.clone(),
            dnstap_sender: resolver_core.dnstap_sender.clone(),
            pending_queries: resolver_core.pending_queries.clone(),
            waiting_clients_count: resolver_core.waiting_clients_count.clone(),
            upstream_servers_arc: resolver_core.upstream_servers_arc.clone(),
            cache: resolver_core.cache.clone(),
            varz: resolver_core.varz.clone(),
            decrement_ttl: resolver_core.decrement_ttl,
            local_port: local_port,
            net_udp_socket: resolver_core.net_udp_socket.try_clone().unwrap(),
        }
    }

    pub fn fut_process_stream<'a>(mut self,
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

    fn verify_ext_response(&self,
                           pending_query: &PendingQuery,
                           packet: &[u8],
                           client_addr: SocketAddr)
                           -> Result<(), String> {
        debug_assert!(packet.len() >= DNS_QUERY_MIN_SIZE);
        if self.local_port != pending_query.local_port {
            return Err(format!("Got a reponse on port {} for a query sent on port {}",
                               self.local_port,
                               pending_query.local_port));
        }
        if client_addr != pending_query.socket_addr {
            return Err(format!("Sent a query to {:?} but got a response from {:?}",
                               pending_query.socket_addr,
                               client_addr));

        }
        if pending_query.normalized_question_minimal.tid != tid(&packet) {
            return Err(format!("Sent a query with tid {} but got a response for tid {:?}",
                               pending_query.normalized_question_minimal.tid,
                               tid(&packet)));
        }
        Ok(())
    }

    fn upstream_idx_from_client_addr(&self, client_addr: SocketAddr) -> Option<usize> {
        self.upstream_servers_arc
            .lock()
            .unwrap()
            .iter()
            .position(|upstream_server| upstream_server.socket_addr == client_addr)
    }

    fn clamped_ttl(&self, mut packet: &mut [u8]) -> Result<u32, &'static str> {
        match min_ttl(&packet,
                      self.config.min_ttl,
                      self.config.max_ttl,
                      FAILURE_TTL) {
            Err(_) => {
                self.varz.upstream_errors.inc();
                Err("Unexpected RRs in a response")
            }
            Ok(ttl) => {
                if rcode(&packet) == DNS_RCODE_SERVFAIL {
                    let _ = set_ttl(&mut packet, FAILURE_TTL);
                    Ok(FAILURE_TTL)
                } else if ttl < self.config.min_ttl {
                    if self.decrement_ttl {
                        let _ = set_ttl(&mut packet, self.config.min_ttl);
                    }
                    Ok(self.config.min_ttl)
                } else {
                    Ok(ttl)
                }
            }
        }
    }

    fn store_to_cache(&mut self,
                      packet: Vec<u8>,
                      normalized_question_key: NormalizedQuestionKey,
                      ttl: u32) {
        if rcode(&packet) == DNS_RCODE_SERVFAIL {
            match self.cache.get(&normalized_question_key) {
                None => {
                    self.cache
                        .insert(normalized_question_key, packet, FAILURE_TTL);
                }                
                Some(cache_entry) => {
                    self.varz.client_queries_offline.inc();
                    self.cache
                        .insert(normalized_question_key, cache_entry.packet, FAILURE_TTL);
                }
            }
        } else {
            self.cache.insert(normalized_question_key, packet, ttl);
        }
        self.update_cache_stats();
    }

    fn dispatch_client_query(&self,
                             mut packet: &mut [u8],
                             client_query: &ClientQuery)
                             -> Result<(), &'static str> {
        self.varz.upstream_received.inc();
        client_query.response_send(&mut packet, &self.net_udp_socket);
        Ok(())
    }

    fn dispatch_client_queries(&self,
                               mut packet: &mut [u8],
                               client_queries: &Vec<ClientQuery>)
                               -> Result<(), &'static str> {
        for client_query in client_queries {
            let _ = self.dispatch_client_query(packet, client_query);
        }
        Ok(())
    }

    fn dispatch_pending_query(&mut self,
                              mut packet: &mut [u8],
                              normalized_question_key: &NormalizedQuestionKey,
                              client_addr: SocketAddr)
                              -> Result<(), &'static str> {
        let map = self.pending_queries.map_arc.lock().unwrap();
        let pending_query = match map.get(&normalized_question_key) {
            None => return Err("No clients waiting for this query"),                
            Some(pending_query) => pending_query,
        };
        if self.verify_ext_response(&pending_query, &packet, client_addr)
               .is_err() {
            return Err("Received response is not valid for the query originally sent");
        }
        if let Some(ref dnstap_sender) = self.dnstap_sender {
            dnstap_sender.send_forwarder_response(&packet, client_addr, self.local_port);
        }
        let client_queries = &pending_query.client_queries;
        self.dispatch_client_queries(&mut packet, client_queries)
    }

    fn fut_process_ext_socket(&mut self,
                              packet: Rc<Vec<u8>>,
                              client_addr: SocketAddr)
                              -> Box<Future<Item = (), Error = io::Error>> {
        debug!("received on an external socket {:?}", packet);
        if packet.len() < DNS_QUERY_MIN_SIZE {
            info!("Short response received over UDP");
            self.varz.upstream_errors.inc();
            return Box::new(future::ok((())));
        }
        if self.upstream_idx_from_client_addr(client_addr).is_none() {
            debug!("Got a response from an unexpected upstream server");
            return Box::new(future::ok((())));
        }
        let normalized_question = match normalize(&packet, false) {
            Err(e) => {
                info!("Unexpected question in a response: {}", e);
                return Box::new(future::ok((())));
            }
            Ok(normalized_question) => normalized_question,
        };
        let mut packet = (*packet).clone();
        let ttl = match self.clamped_ttl(&mut packet) {
            Err(e) => {
                info!("Unable to compute a TTL for caching a response: {}", e);
                return Box::new(future::ok((())));
            }
            Ok(ttl) => ttl,
        };
        let normalized_question_key = normalized_question.key();
        self.dispatch_pending_query(&mut packet, &normalized_question_key, client_addr)
            .unwrap_or_else(|e| debug!("Couldn't dispatch response: {}", e));
        if let Ok(mut map) = self.pending_queries.map_arc.lock() {
            if let Some(pending_query) = map.remove(&normalized_question_key) {
                let _ = pending_query.done_tx.send(());
                let clients_count = pending_query.client_queries.len();
                let prev_count = self.waiting_clients_count
                    .fetch_sub(clients_count, Relaxed);
                assert!(prev_count >= clients_count);
            }
        }
        self.store_to_cache(packet, normalized_question_key, ttl);
        Box::new(future::ok((())))
    }

    fn update_cache_stats(&mut self) {
        let cache_stats = self.cache.stats();
        self.varz
            .cache_frequent_len
            .set(cache_stats.frequent_len as f64);
        self.varz
            .cache_recent_len
            .set(cache_stats.recent_len as f64);
        self.varz
            .cache_test_len
            .set(cache_stats.test_len as f64);
        self.varz
            .cache_inserted
            .set(cache_stats.inserted as f64);
        self.varz.cache_evicted.set(cache_stats.evicted as f64);
    }
}
