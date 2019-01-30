use byteorder::BigEndian;
use bytes::{Bytes, BytesMut};
use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    cipher::CipherMethod::{self, *},
    new_aead_decryptor,
    new_aead_encryptor,
};
use futures::task::{LocalWaker, Poll};
use std::io;

const MAX_SHADOWSOCK_PACKET_SIZE: usize = 0x3fff;

pub struct AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    reader: R,
    cipher: Box<AeadDecryptor>,
    tag_len: usize,
    buffer: [0u8; SS_TCP_CHUNK_LEN],
    pos: usize,
}

impl<R> AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    pub fn new(r: R, method: CipherMethod, key_derive_from_pass: Bytes, salt: Bytes) -> Self {
        let tag_len = method.tag_len();
        AeadDecryptedReader {
            reader: r,
            cipher: new_aead_decryptor(method, &key_derive_from_pass, &salt),
            tag_len,
            pos: 0,
        }
    }
}

impl<R> AsyncRead for AeadDecryptedReader<R>
where
    R: AsyncRead,
{
    fn pool_read(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, io::Error>> {}
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
