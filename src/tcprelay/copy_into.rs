use futures::{
    future::{FusedFuture, Future},
    io::{AsyncRead, AsyncWrite},
    ready,
    task::{LocalWaker, Poll},
    try_ready,
};
use std::{
    boxed::Box,
    io::{self, ErrorKind},
    marker::Unpin,
    pin::Pin,
};
/// A future which will copy all data from a reader into a writer.
///
/// Created by the [`copy_into`] function, this future will resolve to the number of
/// bytes copied or an error if one happens.
///
/// [`copy_into`]: fn.copy_into.html
#[derive(Debug)]
pub struct CopyInto<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    read_done: bool,
    write_done: bool,
    writer: &'a mut W,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
    name: String,
}

// No projections of Pin<&mut CopyInto> into Pin<&mut Field> are ever done.
impl<R: ?Sized, W: ?Sized> Unpin for CopyInto<'_, R, W> {}

impl<'a, R: ?Sized, W: ?Sized> CopyInto<'a, R, W> {
    pub fn new(reader: &'a mut R, writer: &'a mut W, name: String) -> Self {
        CopyInto {
            reader,
            read_done: false,
            write_done: false,
            writer,
            amt: 0,
            pos: 0,
            cap: 0,
            buf: Box::new([0; 2048]),
            #[allow(dead_code)]
            name,
        }
    }
}

impl<R, W> Future for CopyInto<'_, R, W>
where
    R: AsyncRead + ?Sized,
    W: AsyncWrite + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, lw: &LocalWaker) -> Poll<Self::Output> {
        let this = &mut *self;
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if this.pos == this.cap && !this.read_done {
                match ready!(this.reader.poll_read(lw, &mut this.buf)) {
                    Ok(n) => {
                        if n == 0 {
                            this.read_done = true;
                        } else {
                            this.pos = 0;
                            this.cap = n;
                        }
                    }

                    Err(e) => {
                        if e.kind() == ErrorKind::WouldBlock {
                            return Poll::Pending;
                        } else {
                            this.read_done = true;
                            this.write_done = this.pos == this.cap;
                        }
                    }
                }
            }

            // If our buffer has some data, let's write it out!
            while this.pos < this.cap {
                match ready!(this.writer.poll_write(lw, &this.buf[this.pos..this.cap])) {
                    Ok(n) => {
                        if n == 0 {
                            this.read_done = true;
                            this.write_done = true;
                            return Poll::Ready(Ok(this.amt));
                        } else {
                            this.pos += n;
                            this.amt += n as u64;
                        }
                    }

                    Err(e) => {
                        if e.kind() == ErrorKind::WouldBlock {
                            return Poll::Pending;
                        } else {
                            this.read_done = true;
                            this.write_done = true;

                            return Poll::Ready(Ok(this.amt));
                        }
                    }
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            // done with the entire transfer.
            if this.pos == this.cap && this.read_done {
                this.write_done = true;
                try_ready!(this.writer.poll_flush(lw));
                return Poll::Ready(Ok(this.amt));
            }
        }
    }
}

impl<R, W> FusedFuture for CopyInto<'_, R, W>
where
    R: AsyncRead + ?Sized,
    W: AsyncWrite + ?Sized,
{
    fn is_terminated(&self) -> bool {
        self.write_done && self.read_done
    }
}

pub fn copy_into<'a, R, W>(r: &'a mut R, w: &'a mut W, name: String) -> CopyInto<'a, R, W>
where
    R: AsyncRead + ?Sized,
    W: AsyncWrite + ?Sized,
{
    CopyInto::new(r, w, name)
}
