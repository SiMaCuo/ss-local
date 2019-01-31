use byteorder::BigEndian;
use bytes::{Bytes, BytesMut, Buf, BufMut};
use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    cipher::CipherMethod::{self, *},
    new_aead_decryptor,
    new_aead_encryptor,
};
use futures::{
    task::{LocalWaker, Poll},
    try_ready,
    io,
};
use std::cmp;

//! ppoe connection mtu seem to be 1492, ip header 20, tcp header 20
//! +--------------+---------------+--------------+------------+
//! |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
//! +--------------+---------------+--------------+------------+
//! |      2       |     Fixed     |   Variable   |   Fixed    |
//! +--------------+---------------+--------------+------------+
pub const SS_TCP_CHUNK_LEN: usize = 1452;

const SS_MAX_PACKET_SIZE: usize = 0x3fff;

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
    cipher: Box<AeadDecryptor>,
    dec_data: BytesMut,
    raw_data: BytesMut,
    tag_len: usize,
    pos: usize,
    eof: bool,
}

impl<R> AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    pub fn new(r: R, method: CipherMethod, key_derive_from_pass: Bytes, salt: Bytes) -> Self {
        let tag_len = method.tag_len();
        AeadDecryptedReader {
            reader: r,
            Read_step: ReadingStep::Length,
            cipher: new_aead_decryptor(method, &key_derive_from_pass, &salt),
            dec: BytesMut::with_capacity(SS_TCP_CHUNK_LEN),
            raw: BytesMut::with_capacity(SS_TCP_CHUNK_LEN),
            tag_len,
            pos: 0,
            elf: false,
        }
    }
    
    
    fn read_length(&mut self) -> io::Result<usize> {
        let expect_length = 2 + tag_len;
        
    }
}

impl<R> AsyncRead for AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    fn pool_read(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let copy_len = cmp::min(self.enc_data.len() - pos, buf.len());
        buf.copy_from_slice(&self.enc_data[self.pos..self.pos+copy_len]);
        self.pos += copy_len;
        if self.pos == self.enc_data.len() {
            unsafe {
                self.enc_data.set_len(0);
            }
            self.pos = 0;
        }

        if copy_len == buf.len() {
            return Ready(Ok(copy_len));
        }
        
        self.fill_buf(lw: &LocalWaker, &mut buf[copy_len..])
    }

    fn fill_buf(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {
        let mut 
        while !self.eof {
            match self.read_step {
                ReadingStep::Length => {
                },

                ReadingSetp::Data(dlen) => {
                },
            }
        }
    }

    fn read_exact(&mut self, lw: &LocalWaker, expect_length: usize) -> Poll<Result<usize, io::Error>> {
        
    } 
}

pub struct AeadEncryptorWriter<W>
where
    W: AsyncWrite,
{
    writer: W,
    cipher: Box<AeadEncryptor>,
    tag_len: usize,
}

impl<W> AeadEncryptorWriter<W>
where
    W: AsyncWrite,
{
    pub fn new(w: W, method: CipherMethod, key_derive_from_pass: Bytes, salt: Bytes) -> Self {
        let tag_len = method.tag_len();
        AeadEncryptorWriter {
            writer: w,
            cipher: new_aead_encryptor(method, &key_derive_from_pass, &salt),
            tag_len,
        }
    }
}

impl<W> AsyncWrite for AeadEncryptorWriter<W> where W: AsyncWrite {}
