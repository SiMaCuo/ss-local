#![feature(async_await, await_macro, futures_api)]
use futures::executor;
use log4rs;
use shadowsocks::service;
use crate::acl::{Acl, AclResult};

fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    let acl = Acl::new("gfwlist-banAD.acl").unwrap();
    let mut srv = service::Service::new();

    executor::block_on(
        async {
            await!(srv.serve());
        },
    );

    ()
}
