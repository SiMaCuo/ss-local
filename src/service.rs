use std::io::{self, ErrorKind};

use mio::{Events, Poll, PollOpt, Ready, Token};
use mio::net::{TcpListener, TcpStream};
use slab;

const SERVER: Token = Token(0);
const LOCAL:  Token = Token(1);
const REMOTE: Token = Token(2);
