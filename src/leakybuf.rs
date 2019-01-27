use bytes::BytesMut;
use crossbeam::crossbeam_channel::{bounded, select, Receiver, Sender};
use std::ops::{Deref, DerefMut};

pub struct LeakyBufGuard<'a> {
    chunk: BytesMut,
    leaky: &'a LeakyBuf,
}

impl<'a> LeakyBufGuard<'a> {
    fn new(chunk: BytesMut, leaky: &'a LeakyBuf) -> Self {
        LeakyBufGuard { chunk, leaky }
    }
}

impl<'a> Deref for LeakyBufGuard<'a> {
    type Target = BytesMut;

    fn deref(&self) -> &BytesMut {
        &self.chunk
    }
}

impl<'a> DerefMut for LeakyBufGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.chunk
    }
}

impl<'a> Drop for LeakyBufGuard<'a> {
    fn drop(&mut self) {
        let chunk = std::mem::replace(&mut self.chunk, BytesMut::new());

        self.leaky.put(chunk);
    }
}

pub struct LeakyBuf {
    tx: Sender<BytesMut>,
    rx: Receiver<BytesMut>,
    chunk_len: usize,
}

impl LeakyBuf {
    fn new(chunk_len: usize, capacity: usize) -> Self {
        let (tx, rx) = bounded::<BytesMut>(capacity);
        LeakyBuf { tx, rx, chunk_len }
    }

    pub fn get(&self) -> BytesMut {
        let mut chunk = select! {
            recv(self.rx) -> msg => {
                match msg {
                    Ok(buf) => buf,
                    Err(e) => panic!("can not being here {}", e),
                }
            },

            default => BytesMut::with_capacity(self.chunk_len),
        };

        unsafe {
            chunk.set_len(self.chunk_len);
        }

        chunk
    }

    fn put(&self, chunk: BytesMut) {
        debug_assert!(chunk.capacity() == self.chunk_len);
        if chunk.capacity() != self.chunk_len {
            return;
        }

        select! {
            send(self.tx, chunk) -> _ => {},
            default => {},
        };
    }
}
