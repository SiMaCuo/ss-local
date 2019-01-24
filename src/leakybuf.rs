use std::{
    ops::{Deref, DerefMut, Drop},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    vec::Vec,
};

use bytes::BytesMut;

pub struct LeakyWrap<'a> {
    chunk: BytesMut,
    leaky: &'a mut LeakyBuf,
}

impl<'a> LeakyWrap<'a> {
    fn new(chunk: BytesMut, leaky: &'a mut LeakyBuf) -> Self {
        LeakyWrap { chunk, leaky }
    }
}

impl<'a> Deref for LeakyWrap<'a> {
    type Target = BytesMut;

    fn deref(&self) -> &BytesMut {
        &self.chunk
    }
}

impl<'a> DerefMut for LeakyWrap<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.chunk
    }
}

impl<'a> Drop for LeakyWrap<'a> {
    fn drop(&mut self) {
        // self.leaky.put(self.chunk)
    }
}

pub struct LeakyBuf {
    spin: Arc<AtomicUsize>,
    stack: Vec<BytesMut>,
    chunk_len: usize,
}

impl LeakyBuf {
    fn new(chunk_len: usize, capacity: usize) -> Self {
        LeakyBuf {
            spin: Arc::new(AtomicUsize::new(0)),
            stack: Vec::with_capacity(capacity),
            chunk_len,
        }
    }

    pub fn get(&mut self) -> BytesMut {
        while self.spin.compare_and_swap(0, 1, Ordering::Acquire) != 0 {}

        let mut chunk = if self.stack.len() > 0 {
            self.stack.pop().unwrap()
        } else {
            BytesMut::with_capacity(self.chunk_len)
        };

        unsafe {
            chunk.set_len(self.chunk_len);
        }

        self.spin.store(0, Ordering::Release);

        chunk
    }

    fn put(&mut self, chunk: BytesMut) {
        if chunk.capacity() != self.chunk_len {
            return;
        }

        while self.spin.compare_and_swap(0, 1, Ordering::Acquire) != 0 {}

        if self.stack.len() != self.stack.capacity() {
            self.stack.push(chunk);
        }

        self.spin.store(0, Ordering::Release);
    }
}
