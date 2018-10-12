extern crate tokio;
extern crate bytes;

use bytes::BytesMut;
use tokio::net::TcpStream;

struct Peer {
    stream: TcpStream,
    rd: BytesMut,
    wr: BytesMut,
}

impl Peer {
    fn new(stream: TcpStream) -> Self {
        Peer {
            stream,
            rd: BytesMut::new(),
            wr: BytesMut::new(),
        }
    }
}

