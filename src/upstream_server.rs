use config::Config;
use std::net::SocketAddr;

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

    pub fn live_servers(upstream_servers: &mut Vec<UpstreamServer>) -> Vec<usize> {
        let mut new_live: Vec<usize> = Vec::with_capacity(upstream_servers.len());
        for (idx, upstream_server) in upstream_servers.iter().enumerate() {
            if !upstream_server.offline {
                new_live.push(idx);
            }
        }
        if new_live.is_empty() {
            warn!("No more live servers, trying to resurrect them all");
            for (idx, upstream_server) in upstream_servers.iter_mut().enumerate() {
                upstream_server.offline = false;
                new_live.push(idx);
            }
        }
        info!("Live upstream servers: {:?}", new_live);
        new_live
    }
}
