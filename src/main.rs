extern crate tokio;
extern crate bytes;
extern crate futures;
extern crate mio;
extern crate libc;

pub mod socks5;
pub mod trans;

use tokio::net::TcpListener;
use tokio::prelude::*;
use trans::Transfer;

fn main() {
    let addr = "127.0.0.1:18109".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();
    println!("Listening on: {}", addr);

    let server = listener.incoming()
        .for_each(|stream| {
            println!("accepted socket; addr={:?}", stream.peer_addr().unwrap());
            
            let mut t: Transfer = Transfer::new(stream);
            t.then(move |result| {
                match result {
                    Ok(amt) => {
                        if amt != 0 {
                            println!("read {} bytes", amt);
                        } else {
                            println!("read EOF");
                        }
                    }

                    Err(err) => {
                        println!("error {}", err);
                    }
                }

                Ok(0)
            });

            tokio::spawn(t);
            Ok(())
        })
        .map_err(|e| println!("failed to accept socket; error = {:?}", e));

    println!("server running on localhost:6142");

    tokio::run(server);

}
