use super::{ENC_CHUNK_LEN, buf::BufReader};
use crate::crypto::{BoxAeadDecryptor, BoxAeadEncryptor, cipher::CipherMethod, new_aead_decryptor, new_aead_encryptor};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use core::task::{
    Context,
    Poll::{self, *},
};
use std::{
    io::{Error, ErrorKind},
    pin::Pin,
    task::ready,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
    len: Box<[u8]>,
    tag_len: usize,
}

impl<R> AeadDecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(r: R, method: CipherMethod, key_derive_from_pass: Bytes, salt: Bytes) -> Self {
        let tag_len = method.tag_len();
        AeadDecryptedReader {
            reader: BufReader::new(r),
            read_step: ReadingStep::Length,
            cipher: new_aead_decryptor(method, &key_derive_from_pass, &salt),
            len: Box::from(vec![0u8; 2 + tag_len]),
            tag_len,
        }
    }

    fn decrypt_data(&mut self, cx: &mut Context, out: &mut ReadBuf) -> (Poll<Result<usize, Error>>, usize) {
        let (mut copy_len, bufcap) = (0usize, out.remaining());
        let mut fillbuf_pending = false;
        while copy_len < bufcap {
            match self.read_step {
                ReadingStep::Length => {
                    let expect_len = 2 + self.tag_len;
                    if expect_len > self.reader.len() && !fillbuf_pending {
                        match self.reader.poll_fill_buf(cx) {
                            Ready(Ok(n)) => {
                                if n == 0 {
                                    return (Ready(Ok(0)), copy_len);
                                }
                            }
                            Ready(e) => {
                                return (Ready(e), copy_len);
                            }
                            Pending => {
                                fillbuf_pending = true;
                            }
                        }
                    }

                    if expect_len <= self.reader.len() {
                        let ciphertext = self.reader.buffer();
                        self.len[..expect_len].copy_from_slice(&ciphertext[..expect_len]);
                        let _ = self.cipher.decrypt(&mut self.len[..expect_len]);
                        self.reader.consume(expect_len);

                        let data_len = BigEndian::read_u16(&self.len[..2]) as usize;
                        self.read_step = ReadingStep::Data(data_len);
                    } else {
                        debug_assert!(fillbuf_pending);
                        return (Pending, copy_len);
                    }
                }

                ReadingStep::Data(data_len) => {
                    if data_len > out.remaining() {
                        if fillbuf_pending {
                            return (Pending, copy_len);
                        } else {
                            return (Ready(Ok(copy_len)), copy_len);
                        }
                    }

                    let expect_len = data_len + self.tag_len;
                    if expect_len > self.reader.len() {
                        if !fillbuf_pending {
                            match self.reader.poll_fill_buf(cx) {
                                Ready(Ok(n)) => {
                                    if n == 0 {
                                        // is returning `UnexpectedEof` mandatory when
                                        // hitting EOF mid-way through reading the frame body?
                                        return (Ready(Ok(0)), copy_len);
                                    }
                                }
                                Ready(e) => {
                                    return (Ready(e), copy_len);
                                }
                                Pending => {
                                    fillbuf_pending = true;
                                }
                            }
                        } else {
                            return (Pending, copy_len);
                        }
                    }

                    if expect_len > self.reader.len() {
                        debug_assert!(fillbuf_pending);
                        return (Pending, copy_len);
                    }

                    let ciphertext = self.reader.buffer();
                    let _ = self.cipher.decrypt(&mut ciphertext[..expect_len]);
                    out.put_slice(&ciphertext[..data_len]);
                    copy_len += data_len;
                    self.reader.consume(expect_len);
                    self.read_step = ReadingStep::Length;
                }
            }
        }

        (Ready(Ok(copy_len)), copy_len)
    }
}

impl<R> AsyncRead for AeadDecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<Result<(), Error>> {
        debug_assert!(buf.remaining() > 0);
        let this = &mut *self;

        let (poll, copy_len) = this.decrypt_data(cx, buf);
        match ready!(poll) {
            Ok(0) => {
                return Ready(Err(ErrorKind::UnexpectedEof.into()));
            }
            Err(e) => {
                return Ready(Err(e));
            }
            Ok(_) => {
                debug_assert!(copy_len > 0);
                return Ready(Ok(()));
            }
        }
    }
}

pub struct AeadEncryptorWriter<W>
where
    W: AsyncWrite + Unpin,
{
    writer: W,
    cipher: BoxAeadEncryptor,
    enc_data: Box<[u8]>,
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
        let payload_len = ENC_CHUNK_LEN - 2 - 2 * tag_len;
        AeadEncryptorWriter {
            writer: w,
            cipher: new_aead_encryptor(method, &key_derive_from_pass, &salt),
            enc_data: Box::from(vec![0u8; ENC_CHUNK_LEN]),
            remaining: BytesMut::new(),
            pos: 0,
            payload_len,
            tag_len,
            amt: 0,
        }
    }

    fn write_payload(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, Error>> {
        debug_assert!(buf.len() <= self.payload_len);
        if self.remaining.len() > 0 {
            return Ready(Ok(0));
        }

        let enc_length_end = 2 + self.tag_len;
        BigEndian::write_u16(&mut self.enc_data[..2], buf.len() as u16);
        let _ = self.cipher.encrypt(&mut self.enc_data[..enc_length_end]);

        let enc_cap = enc_length_end + buf.len() + self.tag_len;
        self.enc_data[enc_length_end..enc_length_end + buf.len()].copy_from_slice(buf);
        let _ = self.cipher.encrypt(&mut self.enc_data[enc_length_end..enc_cap]);
        let n = ready!(Pin::new(&mut self.writer).poll_write(cx, &self.enc_data[..enc_cap]))?;
        if n == 0 {
            return Ready(Err(ErrorKind::WriteZero.into()));
        }
        if n != enc_cap {
            self.remaining.extend_from_slice(&self.enc_data[n..enc_cap]);
        }
        self.amt += enc_cap;

        Ready(Ok(buf.len()))
    }

    fn write(&mut self, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let mut total_write = 0usize;
        for i in 0..(buf.len() / self.payload_len) + 1 {
            let boundary = (i + 1) * self.payload_len;
            let end = if boundary > buf.len() { buf.len() } else { boundary };
            let start = i * self.payload_len;
            if start < end {
                let n = ready!(self.write_payload(cx, &buf[start..end]))?;
                total_write += n;
                if n == 0 {
                    break;
                }
            }
            // May wirte zero error, may not be fully written later
        }

        Ready(Ok(total_write))
    }
}

impl<W> AsyncWrite for AeadEncryptorWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let this = &mut *self;
        let remain_len = this.remaining.len();
        while this.pos < remain_len {
            this.pos += ready!(Pin::new(&mut this.writer).poll_write(cx, &this.remaining[this.pos..remain_len]))?;
        }

        this.remaining.clear();
        this.pos = 0;

        this.write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}
