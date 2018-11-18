extern crate mio;
extern crate slab;


pub mod socks5;
pub mod conn;
pub mod service;
pub mod err;


fn main() {

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

                future::ok::<(), ()>(())
            });

            tokio::spawn(t);
            Ok(())
        })
        .map_err(|e| println!("failed to accept socket; error = {:?}", e));

    println!("server running on localhost:6142");

    tokio::run(server);

}
