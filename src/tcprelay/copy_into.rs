use super::buf::DEFAULT_BUF_SIZE;
use futures::{
    future::{FusedFuture, Future},
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, Close},
    task::{Poll, Waker},
};
use std::{
    boxed::Box,
    io::{self, ErrorKind},
    marker::Unpin,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
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
    amt: usize,
    buf: Box<[u8]>,
    quit_mark: Arc<AtomicUsize>,
    #[allow(dead_code)]
    name: String,
}

// No projections of Pin<&mut CopyInto> into Pin<&mut Field> are ever done.
impl<R: ?Sized, W: ?Sized> Unpin for CopyInto<'_, R, W> {}

// impl<'a, R: ?Sized, W: ?Sized> CopyInto<'a, R, W> {
impl<'a, R, W> CopyInto<'a, R, W>
where
    R: AsyncRead + ?Sized,
    W: AsyncWrite + ?Sized,
{
    pub fn new(reader: &'a mut R, writer: &'a mut W, quit_mark: Arc<AtomicUsize>, name: String) -> Self {
        CopyInto {
            reader,
            read_done: false,
            write_done: false,
            writer,
            amt: 0,
            pos: 0,
            cap: 0,
            buf: Box::new([0; DEFAULT_BUF_SIZE]),
            quit_mark,
            name,
        }
    }

    pub fn close(&mut self) -> Close<'_, W> {
        log::debug!("{} close", self.name);
        self.writer.close()
    }
}

impl<R, W> Future for CopyInto<'_, R, W>
where
    R: AsyncRead + ?Sized,
    W: AsyncWrite + ?Sized,
{
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, waker: &Waker) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut poll: Poll<io::Result<usize>> = Poll::Pending;
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if this.pos == this.cap && !this.read_done {
                poll = this
                    .reader
                    .poll_read(waker, &mut this.buf);
                    // .map(|rlt| rlt.map(|n| n as u64));
                match poll {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            log::debug!("{} poll read zero bytes", this.name);
                            this.read_done = true;
                        } else {
                            this.pos = 0;
                            this.cap = n;
                        }
                    }

                    Poll::Ready(Err(ref e)) => {
                        if e.kind() == ErrorKind::WouldBlock {
                            poll = Poll::Pending;
                        } else {
                            log::debug!("{} poll read error: {}", this.name, e);
                            this.read_done = true;
                            this.write_done = this.pos == this.cap;
                        }
                    }

                    Poll::Pending => {}
                }
            }

            // If our buffer has some data, let's write it out!
            while this.pos < this.cap && !this.write_done {
                poll = this
                    .writer
                    .poll_write(waker, &this.buf[this.pos..this.cap]);
                match poll {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            log::debug!("{} poll write zero bytes", this.name);
                            this.read_done = true;
                            this.write_done = true;
                            poll = Poll::Ready(Ok(this.amt));

                            break;
                        } else {
                            this.pos += n;
                            this.amt += n;
                        }
                    }

                    Poll::Ready(Err(ref e)) => {
                        if e.kind() == ErrorKind::WouldBlock {
                            poll = Poll::Pending;

                            break;
                        } else {
                            this.read_done = true;
                            this.write_done = true;
                            log::debug!("{} poll write error: {}", this.name, e);
                            poll = Poll::Ready(Ok(this.amt));

                            break;
                        }
                    }

                    Poll::Pending => {}
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            // done with the entire transfer.
            if this.pos == this.cap && this.read_done {
                this.write_done = true;
                poll = Poll::Ready(Ok(this.amt));
            }

            // if this.quit_mark.load(Ordering::Relaxed) == 0 {
            //     this.write_done = true;
            //     this.read_done = true;
            //     if let Poll::Pending = poll {
            //         poll = Poll::Ready(Ok(0));
            //     }
            
            //     log::debug!("{} peer marked quit, i'm quit {:?}", this.name, poll);
            // } else if this.write_done == true && this.read_done == true {
            //     this.quit_mark.store(0, Ordering::Relaxed);
            
            //     log::debug!("{} mark i'm quit", this.name);
            // }

            if this.write_done {
                let _ = this.writer.poll_flush(waker);
            }

            return poll;
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

pub fn copy_into<'a, R, W>(r: &'a mut R, w: &'a mut W, quit_mark: Arc<AtomicUsize>, name: String) -> CopyInto<'a, R, W>
where
    R: AsyncRead + ?Sized,
    W: AsyncWrite + ?Sized,
{
    CopyInto::new(r, w, quit_mark, name)
}
