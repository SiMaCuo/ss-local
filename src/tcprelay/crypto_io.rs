use crate::crypto::{cipher::CipherMethod, new_aead_decryptor, new_aead_encryptor, BoxAeadDecryptor, BoxAeadEncryptor};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{
    io,
    prelude::*,
    task::{
        LocalWaker,
        Poll::{self, *},
    },
    try_ready,
};
use std::{cmp, io::ErrorKind};

// ppoe connection mtu seem to be 1492, ip header 20, tcp header 20
// +--------------+---------------+--------------+------------+
// |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
// +--------------+---------------+--------------+------------+
// |      2       |     Fixed     |   Variable   |   Fixed    |
// +--------------+---------------+--------------+------------+
pub const SS_TCP_CHUNK_LEN: usize = 1452;

const SS_MAX_PACKET_LEN: usize = 0x3fff;

enum ReadingStep {
    Length,
    Data(usize),
    Done,
}

pub struct AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    reader: R,
    read_step: ReadingStep,
    cipher: BoxAeadDecryptor,
    dec: BytesMut,
    data: BytesMut,
    tag_len: usize,
    pos: usize,
    eof: bool,
    amt: usize,
}

impl<R> AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    pub fn new(r: R, method: CipherMethod, key_derive_from_pass: Bytes, salt: Bytes) -> Self {
        let tag_len = method.tag_len();
        AeadDecryptedReader {
            reader: r,
            read_step: ReadingStep::Length,
            cipher: new_aead_decryptor(method, &key_derive_from_pass, &salt),
            dec: BytesMut::with_capacity(SS_TCP_CHUNK_LEN),
            data: BytesMut::with_capacity(SS_TCP_CHUNK_LEN),
            tag_len,
            pos: 0,
            eof: false,
            amt: 0,
        }
    }

    fn read_length(&mut self, lw: &LocalWaker) -> Poll<Result<usize, io::Error>> {
        let expect_len = 2 + self.tag_len;
        if self.data.len() - self.pos < expect_len {
            self.data.split_off(self.pos);
            self.data.reserve(SS_TCP_CHUNK_LEN - self.data.len());
            self.pos = 0;
        }
        let read_len = unsafe {
            let n = try_ready!(self.reader.poll_read(lw, self.data.bytes_mut()));
            self.data.advance_mut(n);
            n
        };

        if read_len == 0 {
            self.eof = true;
            return Ready(Err(ErrorKind::UnexpectedEof.into()));
        }

        if self.data.len() - self.pos < expect_len {
            return Pending;
        }

        let mut out = [0u8; 2];
        let _ = self
            .cipher
            .decrypt(&mut self.data[self.pos..self.pos + expect_len], &mut out);
        self.pos += expect_len;
        self.amt += expect_len;
        Ready(Ok(BigEndian::read_u16(&out) as usize))
    }

    fn read_data(&mut self, lw: &LocalWaker, data_len: usize, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let expect_len = data_len + self.tag_len;
        if self.data.len() - self.pos < expect_len {
            self.data.split_off(self.pos);
            self.data.reserve(SS_TCP_CHUNK_LEN - self.data.len());
            self.pos = 0;
        }

        let read_len = unsafe {
            let n = try_ready!(self.reader.poll_read(lw, self.data.bytes_mut()));
            self.data.advance_mut(n);
            n
        };

        if read_len == 0 {
            self.eof = true;
            return Ready(Err(ErrorKind::UnexpectedEof.into()));
        }

        if self.data.len() - self.pos < expect_len {
            return Pending;
        }

        if data_len <= buf.len() {
            let _ = self
                .cipher
                .decrypt(&mut self.data[self.pos..self.pos + expect_len], &mut buf[..data_len]);
        } else {
            let mut out = BytesMut::with_capacity(data_len);
            unsafe {
                let _ = self
                    .cipher
                    .decrypt(&mut self.data[self.pos..self.pos + expect_len], &mut out.bytes_mut());
            }
            buf.copy_from_slice(&out[..buf.len()]);
            self.dec.put_slice(&out[buf.len()..])
        }

        self.pos += expect_len;
        if self.pos == self.data.len() {
            self.pos = 0;
            unsafe {
                self.data.set_len(0);
            }
        }
        self.amt += expect_len;
        Ready(Ok(data_len))
    }

    fn fill_buf(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        // while !self.eof {
        //     match self.read_step {
        //         ReadingStep::Length => {
        //             let data_len = try_ready!(self.read_length(lw));
        //             self.read_step = ReadingStep::Data(data_len);
        //             debug_assert!(data_len <= SS_TCP_CHUNK_LEN);
        //         }
        //
        //         ReadingStep::Data(dlen) => {
        //             try_ready!(self.read_data(lw, dlen, buf));
        //         }
        //
        //         ReadingStep::Done => {
        //             self.read_step = ReadingStep::Length;
        //             break;
        //         }
        //     }
        // }
        //
        self.reader.poll_read(lw, buf)
    }
}

impl<R> AsyncRead for AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    fn poll_read(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        debug_assert!(buf.len() > 0);

        let copy_len = cmp::min(self.dec.len(), buf.len());
        if copy_len > 0 {
            buf.copy_from_slice(&self.dec[..copy_len]);
            self.dec.split_off(copy_len);

            if copy_len == buf.len() {
                return Ready(Ok(copy_len));
            }
        }

        self.fill_buf(lw, &mut buf[copy_len..])
    }
}

pub struct AeadEncryptorWriter<W>
where
    W: AsyncWrite,
{
    writer: W,
    cipher: BoxAeadEncryptor,
    enc_chunk: BytesMut,
    payload_len: usize,
    tag_len: usize,
    amt: usize,
}

impl<W> AeadEncryptorWriter<W>
where
    W: AsyncWrite,
{
    pub fn new(w: W, method: CipherMethod, key_derive_from_pass: Bytes, salt: Bytes) -> Self {
        let tag_len = method.tag_len();
        let payload_len = SS_TCP_CHUNK_LEN - 2 - 2 * tag_len;
        AeadEncryptorWriter {
            writer: w,
            cipher: new_aead_encryptor(method, &key_derive_from_pass, &salt),
            enc_chunk: BytesMut::with_capacity(SS_TCP_CHUNK_LEN),
            payload_len,
            tag_len,
            amt: 0,
        }
    }

    fn write_all(&mut self, lw: &LocalWaker, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        debug_assert!(buf.len() <= self.payload_len);
        self.enc_chunk.clear();
        let mut length = [0u8; 2];
        BigEndian::write_u16(&mut length, buf.len() as u16);
        unsafe {
            let _ = self
                .cipher
                .encrypt(&length, &mut self.enc_chunk.bytes_mut()[..2 + self.tag_len]);
            self.enc_chunk.advance_mut(2 + self.tag_len);
            let _ = self.cipher.encrypt(
                buf,
                &mut self.enc_chunk.bytes_mut()[2 + self.tag_len..2 + 2 * self.tag_len + buf.len()],
            );
            self.enc_chunk.advance_mut(buf.len() + self.tag_len);
        }

        let mut pos = 0;
        while pos < self.enc_chunk.len() {
            pos += try_ready!(self.writer.poll_write(lw, &self.enc_chunk[..]));
        }

        Ready(Ok(buf.len()))
    }
}

impl<W> AsyncWrite for AeadEncryptorWriter<W>
where
    W: AsyncWrite,
{
    fn poll_write(&mut self, lw: &LocalWaker, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        // let loop_count = buf.len() / self.payload_len;
        // for index in 0..loop_count {
        //     self.amt += try_ready!(self.write_all(lw, &buf[index * self.payload_len..(index + 1) * self.payload_len]));
        // }
        //
        // self.amt += try_ready!(self.write_all(
        //     lw,
        //     &buf[loop_count * self.payload_len..(loop_count + 1) * self.payload_len]
        // ));
        //
        // Ready(Ok(buf.len()))
        self.writer.poll_write(lw, buf)
    }

    fn poll_flush(&mut self, lw: &LocalWaker) -> Poll<Result<(), io::Error>> {
        self.writer.poll_flush(lw)
    }

    fn poll_close(&mut self, lw: &LocalWaker) -> Poll<Result<(), io::Error>> {
        self.writer.poll_close(lw)
    }
}
