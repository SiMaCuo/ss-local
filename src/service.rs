use std::io::{self, ErrorKind};

use mio::{Events, Poll, PollOpt, Ready, Token};
use mio::net::{TcpListener, TcpStream};
use slab::*;
use conn::*;

const SERVER: Token = Token(0);

pub struct Service {
    conns: Slab<Connection>,
    
}