mod conn;
mod err;
mod rccell;
mod service;
mod socks5;

fn main() {
    let mut srv = service::Service::new();
    let _ = srv.serve();

    ()
}
