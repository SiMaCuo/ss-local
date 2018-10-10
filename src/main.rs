extern crate tokio;
extern crate bytes;

use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio::codec::BytesCodec;
use tokio::codec::Decoder;

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

fn main() {
    let addr = "127.0.0.1:18109".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();
    println!("Listening on: {}", addr);

    let server = listener.incoming()
        .map_err(|e| println!("failed to accept socket; error = {:?}", e))
        .for_each(|stream| {
            println!("accepted socket; addr={:?}", stream.peer_addr().unwrap());
            let frame = BytesCodec::new().framed(stream);
            let (_, splitstream) = frame.split();
            
            let processor = splitstream.for_each(|bytes| {
                println!("bytes: {:?}", bytes);
                Ok(())
            })
            .and_then(|()| {
                println!("Socket received FIN packet and closed connection.");
                Ok(())
            })
            .or_else(|err| {
                println!("socket closed with error: {:?}", err);
                Err(err)
            })
            .then(|result| {
                println!("socket closed with result: {:?}", result);
                Ok(())
            });

            tokio::spawn(processor)
        });

    println!("server running on localhost:6142");

    tokio::run(server);

}
