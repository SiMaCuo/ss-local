use log4rs;

mod conn;
mod err;
mod rccell;
mod service;
mod shut;
mod socks5;
mod config;

fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    let mut srv = service::Service::new();
    let _ = srv.serve();

    ()
}
