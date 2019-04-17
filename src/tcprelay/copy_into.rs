use super::buf::DEFAULT_BUF_SIZE;
use futures::{
    future::{FusedFuture, Future},
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, Close},
    ready,
    task::{Context, Poll},
    try_ready,
};
use std::{
    boxed::Box,
    io,
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
    R: AsyncRead + ?Sized + Unpin,
    W: AsyncWrite + ?Sized + Unpin,
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

    pub fn close(&mut self) -> Close<'_, W>
    where
        Self: Unpin,
    {
        log::debug!("{} close.", self.name);
        self.writer.close()
    }
}

impl<R, W> Future for CopyInto<'_, R, W>
where
    R: AsyncRead + ?Sized + Unpin,
    W: AsyncWrite + ?Sized + Unpin,
{
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.quit_mark.load(Ordering::Relaxed) == 0 {
            this.write_done = true;
            this.read_done = true;

            return Poll::Ready(Ok(this.amt));
        }

        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if this.pos == this.cap && !this.read_done {
                let _ready = Pin::new(&mut this.reader).poll_read(cx, &mut this.buf);
                log::debug!("{}, poll read {:?}", this.name, _ready);
                match ready!(_ready) {
                    Ok(n) if n > 0 => {
                        this.pos = 0;
                        this.cap = n;
                    }

                    _ => {
                        this.read_done = true;

                        log::debug!("{}, poll read done", this.name,);
                    }
                }
            }

            // If our buffer has some data, let's write it out!
            while this.pos < this.cap {
                let _ready = Pin::new(&mut this.writer).poll_write(cx, &this.buf[this.pos..this.cap]);
                log::debug!("{}, poll write {:?}", this.name, _ready);
                match ready!(_ready) {
                    Ok(n) if n > 0 => {
                        this.pos += n;
                        this.amt += n;
                    }

                    _ => {
                        this.write_done = true;
                        this.read_done = true;
                        log::debug!("{}, poll write done", this.name,);
                        break;
                    }
                }
            }

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            // done with the entire transfer.
            if this.pos == this.cap && this.read_done && !this.write_done {
                let _ = try_ready!(Pin::new(&mut this.writer).poll_flush(cx));
                this.write_done = true;
            }

            if this.write_done {
                this.quit_mark.store(0, Ordering::Relaxed);

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
        self.write_done
    }
}

pub fn copy_into<'a, R, W>(r: &'a mut R, w: &'a mut W, quit_mark: Arc<AtomicUsize>, name: String) -> CopyInto<'a, R, W>
where
    R: AsyncRead + ?Sized + Unpin,
    W: AsyncWrite + ?Sized + Unpin,
{
    CopyInto::new(r, w, quit_mark, name)
}
