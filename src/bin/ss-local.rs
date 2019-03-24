#![feature(async_await, await_macro, futures_api)]
use clap::{App, Arg};
use futures::executor;
use log::info;
use log4rs;
use shadowsocks::service;
use std::path::{Path, PathBuf};

fn main() {
    let matches = App::new("ss-local")
        .version("0.1.1")
        .author("simacuo")
        .about("shadownsock implementation for learn rustlang")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("user config file, default is files/config.json")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("logconfig")
                .short("-l")
                .long("logconfig")
                .value_name("FILE")
                .help("log config file, default is files/log4rs.yml")
                .takes_value(true),
        )
        .get_matches();

    let dir = {
        let mut p = PathBuf::from(std::env::current_exe().unwrap());
        p.pop();
        p
    };

    let mut log4 = dir.clone();
    log4.push(Path::new(matches.value_of("logconfig").unwrap_or("files/log4rs.yml")));
    if log4.is_file() == false {
        let msg = format!(
            "ss-local log configure file not found at: {:?}, use --help option for more information.",
            log4
        );
        println!("{}", msg);

        return;
    }
    log4rs::init_file(log4, Default::default()).unwrap();

    let mut conf = dir.clone();
    conf.push(Path::new(matches.value_of("config").unwrap_or("files/config.json")));
    if conf.is_file() == false {
        let msg = format!(
            "ss-local configure file not found at: {:?}, use --help option for more information.",
            conf
        );
        println!("{}", msg);
        info!("{}", msg);

        return;
    }

    let _ = service::Service::new(dir, &conf)
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
