use coarsetime::Instant;
use dns::{self, NormalizedQuestion};
use futures::{future, Future};
use futures::sync::mpsc::Sender;
use resolver::*;
use std::io;
use std::net::{self, SocketAddr};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ClientQueryProtocol {
    UDP,
    TCP,
}

#[derive(Clone, Debug)]
pub struct ClientQuery {
    pub proto: ClientQueryProtocol,
    pub client_addr: Option<SocketAddr>,
    pub tcpclient_tx: Option<Sender<ResolverResponse>>,
    pub normalized_question: NormalizedQuestion,
    pub ts: Instant,
}

impl ClientQuery {
    pub fn udp(client_addr: SocketAddr, normalized_question: NormalizedQuestion) -> Self {
        ClientQuery {
            proto: ClientQueryProtocol::UDP,
            client_addr: Some(client_addr),
            tcpclient_tx: None,
            normalized_question: normalized_question,
            ts: Instant::recent(),
        }
    }

    pub fn tcp(tcpclient_tx: Sender<ResolverResponse>,
               normalized_question: NormalizedQuestion)
               -> Self {
        ClientQuery {
            proto: ClientQueryProtocol::UDP,
            client_addr: None,
            tcpclient_tx: Some(tcpclient_tx),
            normalized_question: normalized_question,
            ts: Instant::recent(),
        }
    }

    pub fn response_send(&self,
                         mut packet: &mut [u8],
                         net_udp_socket: &net::UdpSocket)
                         -> Box<Future<Item = (), Error = io::Error>> {
        let normalized_question = &self.normalized_question;
        let tc_packet;
        let packet = if self.proto == ClientQueryProtocol::UDP &&
                        packet.len() > normalized_question.payload_size as usize {
            tc_packet = dns::build_tc_packet(&normalized_question).unwrap();
            tc_packet.as_ref()
        } else {
            dns::set_tid(&mut packet, normalized_question.tid);
            dns::overwrite_qname(&mut packet, &normalized_question.qname);
            packet
        };
        match self.proto {
            ClientQueryProtocol::UDP => {
                let _ = net_udp_socket.send_to(packet, self.client_addr.unwrap());
            }
            ClientQueryProtocol::TCP => {}
        }
        Box::new(future::ok(()))
    }
}
