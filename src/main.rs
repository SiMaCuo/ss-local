extern crate tokio;
extern crate bytes;

use tokio::net::TcpListener;
use tokio::prelude::*;
use trans::Transfer;

fn main() {
    let addr = "127.0.0.1:18109".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();
    println!("Listening on: {}", addr);

    let server = listener.incoming()
        .map_err(|e| println!("failed to accept socket; error = {:?}", e))
        .for_each(|stream| {
            println!("accepted socket; addr={:?}", stream.peer_addr().unwrap());
            
            let mut t: Transfer = Transfer::new(stream);
            t.then(|()| {
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

            tokio::spawn(t)
        });

    println!("server running on localhost:6142");

    tokio::run(server);

}
