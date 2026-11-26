use super::KB;
use core::task::{
    Context,
    Poll::{self, *},
};
use std::{io::Error, pin::Pin};
use tokio::io::{AsyncRead, ReadBuf};

pub const DEFAULT_BUF_SIZE: usize = 64 * KB;

pub struct BufReader<R> {
    inner: R,
    buf: Box<[u8]>,
    pos: usize,
    end: usize,
    eof: bool,
}

impl<R: AsyncRead + Unpin> BufReader<R> {
    pub fn new(inner: R) -> BufReader<R> {
        BufReader::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    pub fn with_capacity(end: usize, inner: R) -> BufReader<R> {
        BufReader {
            inner,
            buf: Box::from(vec![0u8; end]),
            pos: 0,
            end: 0,
            eof: false,
        }
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> R {
        self.inner
    }

    #[allow(dead_code)]
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    pub fn poll_fill_buf(&mut self, cx: &mut Context) -> Poll<Result<usize, Error>> {
        let mut total_read = 0usize;
        if !self.eof {
            if self.pos >= self.end {
                self.end = 0;
                self.pos = 0;
            }
            if self.pos > 0 {
                self.buf.copy_within(self.pos..self.end, 0);
                self.end = self.end - self.pos;
                self.pos = 0;
            }

            // 当 self.buf 本身已经是满的
            //（self.pos == 0 && self.end == self.buf.len()）时，
            // 返回 Ready(Ok(0)) 会被外层误判为 EOF。

            // 约定：只要真正读到内核 EOF，设置 self.eof = true 并返回 Ready(Ok(0))；
            // 而如果是因为缓冲区满导致本次 total_read == 0，要么在 decrypt_data
            // 里通过 self.reader.is_eof() 判断真 EOF，要么保证只有在
            // self.reader.len() < expect_len 时才调 poll_fill_buf（确保
            // self.buf 绝不可能是满的，前提是单帧长度不超过 self.buf.len()）
            while self.end < self.buf.len() {
                let mut read_buf = ReadBuf::new(&mut self.buf[self.end..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                    Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            self.eof = true;
                            return Ready(Ok(0));
                        }

                        self.end += n;
                        total_read += n;
                    }
                    Ready(Err(e)) => {
                        return Ready(Err(e));
                    }
                    Pending => {
                        return Pending;
                    }
                }
            }
        }

        Ready(Ok(total_read))
    }

    // #[allow(dead_code)]
    // pub fn fill_buf(&mut self, cx: &mut Context, expect_len: usize) -> Poll<Result<&[u8], Error>> {
    //     debug_assert!(expect_len <= self.buf.len());

    //     if !self.eof {
    //         if self.pos >= self.end {
    //             debug_assert!(self.pos == self.end);
    //             self.end = ready!(Pin::new(&mut self.inner).poll_read(cx, &mut self.buf))?;
    //             self.eof = self.end == 0;
    //             self.pos = 0;
    //         } else if expect_len > self.end - self.pos {
    //             self.buf.copy_within(self.pos..self.end, 0);

    //             self.end = self.end - self.pos;
    //             self.pos = 0;

    //             let read_len = ready!(Pin::new(&mut self.inner).poll_read(cx, &mut self.buf[self.end..]))?;
    //             self.eof = read_len == 0;
    //             self.end += read_len;
    //         }
    //     }

    //     Ready(Ok(&self.buf[self.pos..self.end]))
    // }

    pub fn buffer(&mut self) -> &mut [u8] {
        &mut self.buf[self.pos..self.end]
    }

    pub fn len(&self) -> usize {
        self.end - self.pos
    }

    pub fn consume(&mut self, amt: usize) {
        self.pos = (self.pos + amt).min(self.end);
    }
}
