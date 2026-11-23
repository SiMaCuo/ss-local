use core::task::{
    Context,
    Poll::{self, *},
};
use smol::{
    io::{AsyncRead, Error},
    ready,
};
use std::{cmp, pin::Pin};

pub const DEFAULT_BUF_SIZE: usize = 4 * 1024;

pub struct BufReader<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
    eof: bool,
}

impl<R: AsyncRead + Unpin> BufReader<R> {
    pub fn new(inner: R) -> BufReader<R> {
        BufReader::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    pub fn with_capacity(cap: usize, inner: R) -> BufReader<R> {
        BufReader {
            inner,
            buf: Box::from(vec![0u8;cap]),
            pos: 0,
            cap: 0,
            eof: false,
        }
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn is_eof(&self) -> bool {
        self.eof
    }

    pub fn fill_buf(&mut self, cx: &mut Context, expect_len: usize) -> Poll<Result<&[u8], Error>> {
        debug_assert!(expect_len <= self.buf.len());

        if !self.eof {
            if self.pos >= self.cap {
                debug_assert!(self.pos == self.cap);
                self.cap = ready!(Pin::new(&mut self.inner).poll_read(cx, &mut self.buf))?;
                self.eof = self.cap == 0;
                self.pos = 0;
            } else if expect_len > self.cap - self.pos {
                self.buf.copy_within(self.pos..self.cap, 0);
                
                self.cap = self.cap - self.pos;
                self.pos = 0;

                let read_len = ready!(Pin::new(&mut self.inner).poll_read(cx, &mut self.buf[self.cap..]))?;
                self.eof = read_len == 0;
                self.cap += read_len;
            }
        }

        Ready(Ok(&self.buf[self.pos..self.cap]))
    }

    pub fn consume(&mut self, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.cap);
    }
}
