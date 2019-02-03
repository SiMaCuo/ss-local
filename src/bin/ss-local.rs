#![feature(async_await, await_macro, futures_api)]
use futures::executor;
use log4rs;
use shadowsocks::service;

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
