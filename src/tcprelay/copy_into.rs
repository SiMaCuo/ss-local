use super::buf::DEFAULT_BUF_SIZE;
use core::task::{Context, Poll};
use std::{
    boxed::Box,
    io::{ErrorKind, Result},
    marker::Unpin,
    pin::Pin,
    // sync::{
    //     Arc,
    //     atomic::{AtomicUsize, Ordering},
    // },
    task::ready,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A future which will copy all data from a reader into a writer.
///
/// Created by the [`copy_into`] function, this future will resolve to the number of
/// bytes copied or an error if one happens.
///
/// [`copy_into`]: fn.copy_into.html
#[derive(Debug)]
pub struct CopyInto<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    read_done: bool,
    #[allow(dead_code)]
    write_done: bool,
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
    amt: usize,
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
    pub fn new(reader: &'a mut R, writer: &'a mut W, name: String) -> Self {
        CopyInto {
            reader,
            writer,
            read_done: false,
            write_done: false,
            buf: Box::new([0; DEFAULT_BUF_SIZE]),
            pos: 0,
            cap: 0,
            amt: 0,
            name,
        }
    }

    // pub fn close(&mut self) -> CloseFuture<'_, W>
    // where
    //     Self: Unpin,
    // {
    //     log::debug!("{} close.", self.name);
    //     self.writer.close()
    // }
}

impl<R, W> Future for CopyInto<'_, R, W>
where
    R: AsyncRead + ?Sized + Unpin,
    W: AsyncWrite + ?Sized + Unpin,
{
    type Output = Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = &mut *self;

        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if this.pos == this.cap && !this.read_done {
                let mut read_buf = ReadBuf::new(&mut this.buf);
                let _ready = Pin::new(&mut this.reader).poll_read(cx, &mut read_buf);
                log::debug!("{}, poll read {:?}", this.name, _ready);
                match ready!(_ready) {
                    Ok(()) if !read_buf.filled().is_empty() => {
                        this.pos = 0;
                        this.cap = read_buf.filled().len();
                    }
                    Ok(()) => {
                        // reading EOF
                        this.read_done = true;
                    }
                    Err(e) => {
                        log::debug!("{}, poll read done, {:?}", this.name, e);
                        this.read_done;
                    }
                }
            }

            // If our buffer has some data, let's write it out!
            while this.pos < this.cap {
                let _ready = Pin::new(&mut this.writer).poll_write(cx, &this.buf[this.pos..this.cap]);
                log::debug!("{}, poll write {:?}", this.name, _ready);
                match ready!(_ready) {
                    Ok(n) => {
                        this.pos += n;
                        this.amt += n;
                        if n == 0 {
                            return Poll::Ready(Err(ErrorKind::WriteZero.into()));
                        }
                    }
                    Err(e) => {
                        log::debug!("{}, poll write done, {:?}", this.name, e);
                        return Poll::Ready(Err(e));
                    }
                }
            }

            if this.pos == this.cap && this.read_done {
                // let _ = ready!(Pin::new(&mut this.writer).poll_flush(cx))?;
                // let _ = ready!(Pin::new(&mut this.writer).poll_shutdown(cx));
                return Poll::Ready(Ok(this.amt));
            }
        }
    }
}

// impl<R, W> FusedFuture for CopyInto<'_, R, W>
// where
//     R: AsyncRead + ?Sized + Unpin,
//     W: AsyncWrite + ?Sized + Unpin,
// {
//     fn is_terminated(&self) -> bool {
//         self.write_done
//     }
// }

pub fn copy_into<'a, R, W>(r: &'a mut R, w: &'a mut W, name: String) -> CopyInto<'a, R, W>
where
    R: AsyncRead + ?Sized + Unpin,
    W: AsyncWrite + ?Sized + Unpin,
{
    CopyInto::new(r, w, name)
}
