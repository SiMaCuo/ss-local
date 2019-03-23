#![feature(async_await, await_macro, futures_api)]
use futures::executor;
use log::info;
use log4rs;
use shadowsocks::service;

fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    let _ = service::Service::new()
        .map_err(|err| {
            println!("launch failed: {}", err);
            info!("launch failed: {}", err);

            err
        })
        .and_then(|mut srv| {
            executor::block_on(
                async {
                    await!(srv.serve());
                },
            );

            Ok(())
        });
}
