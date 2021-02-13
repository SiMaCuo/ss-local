use super::{buf::BufReader, SS_TCP_CHUNK_LEN};
use crate::crypto::{cipher::CipherMethod, new_aead_decryptor, new_aead_encryptor, BoxAeadDecryptor, BoxAeadEncryptor};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use core::task::{
    Context,
    Poll::{self, *},
};
use smol::{io, prelude::*, ready};
use std::{io::ErrorKind, pin::Pin};

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
    R: AsyncRead + Unpin,
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
    poll: Option<Poll<Result<usize, io::Error>>>,
}

impl<R> AeadDecryptedReader<R>
where
    R: AsyncRead + Unpin,
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
            poll: None,
        }
    }

    fn read_length(&mut self, cx: &mut Context) -> Poll<Result<usize, io::Error>> {
        let expect_len = 2 + self.tag_len;
        loop {
            let ciphertext = ready!(self.reader.fill_buf(cx, expect_len))?;
            if ciphertext.len() >= expect_len {
                self.len[..expect_len].copy_from_slice(&ciphertext[..expect_len]);
                let _ = self.cipher.decrypt(&mut self.len[..expect_len]);
                self.reader.consume(expect_len);
                self.amt += expect_len;

                return Ready(Ok(BigEndian::read_u16(&self.len[..2]) as usize));
            }

            if self.reader.is_eof() {
                return Ready(Err(ErrorKind::UnexpectedEof.into()));
            }
        }
    }

    fn read_data(&mut self, cx: &mut Context, data_len: usize, out: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let expect_len = data_len + self.tag_len;
        debug_assert!(expect_len <= SS_TCP_CHUNK_LEN);

        loop {
            let ciphertext = ready!(self.reader.fill_buf(cx, expect_len))?;
            if ciphertext.len() >= expect_len {
                let out_len = out.len();
                let rlt = if out_len >= expect_len {
                    &mut out[..expect_len].copy_from_slice(&ciphertext[..expect_len]);
                    let _ = self.cipher.decrypt(&mut out[..expect_len]);

                    Ok(data_len)
                } else {
                    self.dec[..expect_len].copy_from_slice(&ciphertext[..expect_len]);
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
        }
    }

    fn decrypt_data(&mut self, cx: &mut Context, buf: &mut [u8]) -> (Poll<Result<usize, io::Error>>, usize) {
        let (mut copy_len, cap) = (0usize, buf.len());
        while copy_len < cap {
            match self.read_step {
                ReadingStep::Length => match self.read_length(cx) {
                    Ready(Ok(data_len)) => {
                        log::debug!("  decrypt data length {}", data_len);
                        if data_len == 0 {
                            return (Ready(Ok(0)), copy_len);
                        }

                        self.read_step = ReadingStep::Data(data_len);
                    }

                    Ready(Err(e)) => {
                        log::debug!(" decrypt data lenth ({:?}, {})", e, copy_len);
                        return (Ready(Err(e)), copy_len);
                    }

                    Pending => {
                        log::debug!(" decrypt data len (Pending, {})", copy_len);
                        return (Pending, copy_len);
                    }
                },

                ReadingStep::Data(data_len) => match self.read_data(cx, data_len, &mut buf[copy_len..]) {
                    Ready(Ok(n)) => {
                        if n == 0 {
                            return (Ready(Ok(0)), copy_len);
                        }
                        log::debug!("  decrypt payload {} bytes", n);
                        copy_len += n;
                        self.read_step = ReadingStep::Length;
                    }

                    Ready(Err(e)) => {
                        log::debug!(" decrypt payload ({:?}, {})", e, copy_len);
                        return (Ready(Err(e)), copy_len);
                    }

                    Pending => {
                        log::debug!(" decrypt payload (Pending, {})", copy_len);
                        return (Pending, copy_len);
                    }
                },
            }
        }

        return (Ready(Ok(copy_len)), copy_len);
    }
}

impl<R> AsyncRead for AeadDecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        debug_assert!(buf.len() > 0);
        let this = &mut *self;
        if this.cap - this.pos > 0 {
            let len = std::cmp::min(this.cap - this.pos, buf.len());
            &mut buf[..len].copy_from_slice(&this.dec[this.pos..this.pos + len]);
            this.pos += len;

            if this.pos >= this.cap {
                this.pos = 0;
                this.cap = 0;
            }

            log::debug!("  still has data");
            return Ready(Ok(len));
        }

        if this.poll.is_some() {
            unsafe {
                return std::ptr::replace(&mut this.poll, None).unwrap();
            }
        }

        let (poll, copy_len) = this.decrypt_data(cx, buf);
        if copy_len == 0 {
            return poll;
        }

        if let Pending = poll {
            this.poll = Some(Pending);
        }

        Ready(Ok(copy_len))
    }
}

pub struct AeadEncryptorWriter<W>
where
    W: AsyncWrite + Unpin,
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
    W: AsyncWrite + Unpin,
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

    fn write_payload(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
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
        let n = ready!(Pin::new(&mut self.writer).poll_write(cx, &enc_data[..enc_cap]))?;
        if n == 0 {
            return Ready(Err(ErrorKind::WriteZero.into()));
        }
        if n != enc_cap {
            self.remaining.reserve(enc_cap - n);
            unsafe {
                self.remaining.bytes_mut()[..enc_cap - n].copy_from_slice(&enc_data[n..enc_cap]);
                self.remaining.advance_mut(enc_cap - n);
            }
        }
        self.amt += enc_cap;

        Ready(Ok(buf.len()))
    }

    fn write(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let mut total_write = 0usize;
        for i in 0..(buf.len() / self.payload_len) + 1 {
            let boundary = (i + 1) * self.payload_len;
            let end = if boundary > buf.len() { buf.len() } else { boundary };

            let n = ready!(self.write_payload(cx, &buf[i * self.payload_len..end]))?;
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
    W: AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let this = &mut *self;
        let remain_len = this.remaining.len();
        while this.pos < remain_len {
            this.pos += ready!(Pin::new(&mut this.writer).poll_write(cx, &this.remaining[this.pos..remain_len]))?;
        }

        this.remaining.clear();
        this.pos = 0;

        this.write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().writer).poll_close(cx)
    }
}
