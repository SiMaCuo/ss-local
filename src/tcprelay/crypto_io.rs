use super::{buf::BufReader, SS_TCP_CHUNK_LEN};
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
use std::io::ErrorKind;

// +--------------+---------------+--------------+------------+
// |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
// +--------------+---------------+--------------+------------+
// |      2       |     Fixed     |   Variable   |   Fixed    |
// +--------------+---------------+--------------+------------+
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
    len: Box<[u8]>,
    pos: usize,
    cap: usize,
    amt: usize,
    tag_len: usize,
    poll: Poll<Result<usize, io::Error>>,
}

impl<R> AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    pub fn new(r: R, method: CipherMethod, key_derive_from_pass: Bytes, salt: Bytes) -> Self {
        let tag_len = method.tag_len();
        let mut v = Vec::with_capacity(2 + tag_len);
        unsafe {
            v.set_len(2 + tag_len);
        }
        AeadDecryptedReader {
            reader: BufReader::new(r),
            read_step: ReadingStep::Length,
            cipher: new_aead_decryptor(method, &key_derive_from_pass, &salt),
            dec: Box::from([0u8; SS_TCP_CHUNK_LEN]),
            len: v.into_boxed_slice(),
            pos: 0,
            cap: 0,
            amt: 0,
            tag_len,
            poll: Ready(Ok(0)),
        }
    }

    fn read_length(&mut self, lw: &LocalWaker) -> Poll<Result<usize, io::Error>> {
        let expect_len = 2 + self.tag_len;
        let ciphertext = try_ready!(self.reader.fill_buf(lw, expect_len));
        if ciphertext.len() >= expect_len {
            &mut self.len[..expect_len].copy_from_slice(&ciphertext[..expect_len]);
            let _ = self.cipher.decrypt(&mut self.len[..expect_len]);
            self.reader.consume(expect_len);
            self.amt += expect_len;

            return Ready(Ok(BigEndian::read_u16(&self.len[..2]) as usize));
        }

        if self.reader.is_eof() {
            return Ready(Err(ErrorKind::UnexpectedEof.into()));
        }
        
        Pending
    }

    fn read_data(&mut self, lw: &LocalWaker, data_len: usize, out: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let expect_len = data_len + self.tag_len;
        debug_assert!(expect_len <= SS_TCP_CHUNK_LEN);

        let ciphertext = try_ready!(self.reader.fill_buf(lw, expect_len));
        if ciphertext.len() >= expect_len {
            let out_len = out.len();
            let rlt = if out_len >= expect_len {
                &mut out[..expect_len].copy_from_slice(&ciphertext[..expect_len]);
                let _ = self.cipher.decrypt(&mut out[..expect_len]);

                Ok(data_len)
            } else {
                &mut self.dec[..expect_len].copy_from_slice(&ciphertext[..expect_len]);
                let _ = self.cipher.decrypt(&mut self.dec[..expect_len]);
                if out_len >= data_len {
                    &mut out[..data_len].copy_from_slice(&self.dec[..data_len]);
                    Ok(data_len)
                } else {
                    &mut out[..].copy_from_slice(&self.dec[..out_len]);
                    self.cap = data_len;
                    self.pos = out_len;
                    Ok(out_len)
                }
            };

            self.reader.consume(expect_len);
            self.amt += expect_len;

            return Ready(rlt);
        }

        if self.reader.is_eof() {
            return Ready(Err(ErrorKind::UnexpectedEof.into()));
        }

        Pending
    }

    fn decrypt_data(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        match self.poll {
            Ready(Ok(_)) => {}

            Pending | Ready(Err(_)) => {
                return std::mem::replace(&mut self.poll, Ready(Ok(0)));
            }
        }

        let (mut copy_len, cap) = (0usize, buf.len());
        while copy_len < cap {
            match self.read_step {
                ReadingStep::Length => {
                    let poll = self.read_length(lw);
                    match poll {
                        Ready(Ok(data_len)) => {
                            self.read_step = ReadingStep::Data(data_len);
                        }

                        Ready(Err(_)) | Pending if copy_len > 0 => {
                            self.poll = poll;
                            break;
                        }

                        _ => return poll,
                    }
                }

                ReadingStep::Data(data_len) => {
                    let poll = self.read_data(lw, data_len, &mut buf[copy_len..]);
                    match poll {
                        Ready(Ok(n)) => {
                            copy_len += n;
                            self.read_step = ReadingStep::Length;
                        }

                        Ready(Err(_)) | Pending if copy_len > 0 => {
                            self.poll = poll;
                            break;
                        }

                        _ => return poll,
                    }
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
        debug_assert!(buf.len() > 0);

        if self.cap - self.pos > 0 {
            let len = std::cmp::min(self.cap - self.pos, buf.len());
            &mut buf[..len].copy_from_slice(&self.dec[self.pos..self.pos + len]);
            self.pos += len;

            if self.pos >= self.cap {
                self.pos = 0;
                self.cap = 0;
            }

            return Ready(Ok(len));
        }

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
        BigEndian::write_u16(&mut enc_data[..2], buf.len() as u16);
        let _ = self.cipher.encrypt(&mut enc_data[..enc_length_end]);

        let enc_cap = enc_length_end + buf.len() + self.tag_len;
        &mut enc_data[enc_length_end..enc_length_end + buf.len()].copy_from_slice(buf);
        let _ = self.cipher.encrypt(&mut enc_data[enc_length_end..enc_cap]);
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
