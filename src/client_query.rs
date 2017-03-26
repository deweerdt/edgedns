use coarsetime::Instant;
use dns::NormalizedQuestion;
use futures::sync::mpsc::Sender;
use resolver::*;
use std::net::SocketAddr;

#[derive(Copy, Clone, Debug)]
pub enum ClientQueryProtocol {
    UDP,
    TCP,
}

#[derive(Clone)]
pub struct ClientQuery {
    pub proto: ClientQueryProtocol,
    pub client_addr: Option<SocketAddr>,
    pub tcpclient_tx: Option<Sender<ResolverResponse>>,
    pub normalized_question: NormalizedQuestion,
    pub ts: Instant,
}
