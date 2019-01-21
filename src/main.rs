#![feature(async_await, await_macro, futures_api)]
use log4rs;

mod config;
mod conn;
mod err;
mod rccell;
mod service;
mod shut;
mod socks5;

fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    let mut srv = service::Service::new();
    let _ = srv.serve();

    ()
}
