#![feature(async_await, await_macro, futures_api)]
use futures::executor;
use log4rs;

mod config;
mod conn;
mod crypto;
mod err;
mod leakybuf;
mod rccell;
mod service;
mod shut;
mod socks5;

fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    let mut srv = service::Service::new();

    executor::block_on(
        async {
            await!(srv.serve());
        },
    );

    ()
}
