#![feature(async_await, await_macro, futures_api)]
#![feature(box_syntax)]
#![feature(read_initializer)]
#![allow(dead_code)]
#![feature(ip)]

pub mod service;

mod config;
mod crypto;
mod fc;
mod tcprelay;
