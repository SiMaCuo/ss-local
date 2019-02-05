use super::buf::BufReader;
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
}

pub struct AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    reader: BufReader<R>,
    read_step: ReadingStep,
    cipher: BoxAeadDecryptor,
    dec: Box<[u8]>,
    pos: usize,
    cap: usize,
    amt: usize,
    tag_len: usize,
}

impl<R> AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    pub fn new(r: R, method: CipherMethod, key_derive_from_pass: Bytes, salt: Bytes) -> Self {
        let tag_len = method.tag_len();
        AeadDecryptedReader {
            reader: BufReader::new(r),
            read_step: ReadingStep::Length,
            cipher: new_aead_decryptor(method, &key_derive_from_pass, &salt),
            dec: Box::from([0u8; SS_TCP_CHUNK_LEN]),
            pos: 0,
            cap: 0,
            amt: 0,
            tag_len,
        }
    }

    fn read_length(&mut self, lw: &LocalWaker) -> Poll<Result<usize, io::Error>> {
        let expect_len = 2 + self.tag_len;
        let buf = try_ready!(self.reader.fill_buf(lw, expect_len));

        if buf.len() >= expect_len {
            let mut out = [0u8; 2];
            let _ = self.cipher.decrypt(&buf[..expect_len], &mut out);
            self.reader.consume(expect_len);
            self.amt += expect_len;

            return Ready(Ok(BigEndian::read_u16(&out) as usize));
        }

        if self.reader.is_eof() {
            return Ready(Err(ErrorKind::UnexpectedEof.into()));
        }

        Pending
    }

    fn read_data(&mut self, lw: &LocalWaker, data_len: usize, out: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let expect_len = data_len + self.tag_len;
        debug_assert!(expect_len <= SS_TCP_CHUNK_LEN);

        let buf = try_ready!(self.reader.fill_buf(lw, expect_len));
        if buf.len() >= expect_len {
            if data_len <= buf.len() {
                let _ = self.cipher.decrypt(&buf[..expect_len], &mut out[..data_len]);
            } else {
                let _ = self.cipher.decrypt(&buf[..expect_len], &mut self.dec[..]);
                out.copy_from_slice(&self.dec[..buf.len()]);
                self.cap = data_len;
                self.pos = out.len();
            }

            self.reader.consume(expect_len);
            self.amt += expect_len;

            return Ready(Ok(out.len()));
        }

        if self.reader.is_eof() {
            return Ready(Err(ErrorKind::UnexpectedEof.into()));
        }

        Pending
    }

    fn decrypt_data(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let mut copy_len: usize = 0;
        while !self.reader.is_eof() {
            match self.read_step {
                ReadingStep::Length => {
                    let data_len = try_ready!(self.read_length(lw));
                    self.read_step = ReadingStep::Data(data_len);
                }

                ReadingStep::Data(data_len) => {
                    copy_len = try_ready!(self.read_data(lw, data_len, &mut buf[..]));
                    self.read_step = ReadingStep::Length;

                    break;
                }
            }
        }

        Ready(Ok(copy_len))
    }
}

impl<R> AsyncRead for AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    fn poll_read(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let copy_len = cmp::min(self.cap - self.pos, buf.len());
        if copy_len > 0 {
            &mut buf[..copy_len].copy_from_slice(&self.dec[self.pos..self.pos + copy_len]);
            self.pos += copy_len;

            return Ready(Ok(copy_len));
        }

        self.cap = 0;
        self.pos = 0;

        self.decrypt_data(lw, buf)
    }
}

pub struct AeadEncryptorWriter<W>
where
    W: AsyncWrite,
{
    writer: W,
    cipher: BoxAeadEncryptor,
    remaining: BytesMut,
    pos: usize,
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
            remaining: BytesMut::new(),
            pos: 0,
            payload_len,
            tag_len,
            amt: 0,
        }
    }

    fn write_payload(&mut self, lw: &LocalWaker, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        debug_assert!(buf.len() <= self.payload_len);

        if self.remaining.len() > 0 {
            return Ready(Ok(0));
        }

        let mut enc_data = [0u8; SS_TCP_CHUNK_LEN];
        let enc_length_end = 2 + self.tag_len;
        let enc_cap = enc_length_end + buf.len() + self.tag_len;
        let mut length = [0u8; 2];
        BigEndian::write_u16(&mut length, buf.len() as u16);
        let _ = self.cipher.encrypt(&length, &mut enc_data[..enc_length_end]);
        let _ = self.cipher.encrypt(buf, &mut enc_data[enc_length_end..enc_cap]);

        let n = try_ready!(self.writer.poll_write(lw, &enc_data[..enc_cap]));
        if n != enc_cap {
            debug_assert!(self.remaining.len() == 0);
            self.remaining.reserve(enc_cap - n);
            unsafe {
                self.remaining.bytes_mut().copy_from_slice(&enc_data[n..enc_cap]);
            }
        }
        self.amt += enc_cap;

        Ready(Ok(buf.len()))
    }

    fn write(&mut self, lw: &LocalWaker, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let mut total_write = 0usize;
        for i in 0..(buf.len() / self.payload_len) + 1 {
            let boundary = (i + 1) * self.payload_len;
            let end = if boundary > buf.len() { buf.len() } else { boundary };

            let n = try_ready!(self.write_payload(lw, &buf[i * self.payload_len..end]));
            total_write += n;
            // May wirte zero error, may not be fully written later
            if n == 0 {
                break;
            }
        }

        Ready(Ok(total_write))
    }
}

impl<W> AsyncWrite for AeadEncryptorWriter<W>
where
    W: AsyncWrite,
{
    fn poll_write(&mut self, lw: &LocalWaker, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let remain_len = self.remaining.len();
        while self.pos < remain_len {
            self.pos += try_ready!(self.writer.poll_write(lw, &self.remaining[self.pos..remain_len]));
        }

        if self.pos > 0 {
            self.remaining.clear();
            self.pos = 0;
        }

        self.write(lw, buf)
    }

    fn poll_flush(&mut self, lw: &LocalWaker) -> Poll<Result<(), io::Error>> {
        self.writer.poll_flush(lw)
    }

    fn poll_close(&mut self, lw: &LocalWaker) -> Poll<Result<(), io::Error>> {
        self.writer.poll_close(lw)
    }
}
