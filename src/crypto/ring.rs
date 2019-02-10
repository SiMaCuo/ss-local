use super::cipher::CipherMethod::{self, *};
use ring::aead::{open_in_place, seal_in_place, Aad, Nonce, OpeningKey, SealingKey, AES_256_GCM, CHACHA20_POLY1305};

use super::aead::{AeadDecryptor, AeadEncryptor};
use crate::tcprelay::SS_TCP_CHUNK_LEN;
use byte_string::ByteStr;
use bytes::{BufMut, Bytes, BytesMut};
use log::error;
use sodiumoxide::utils::increment_le;
use std::{
    io::{self, Error, ErrorKind},
    ptr,
};

enum RingAeadCryptor {
    Seal(SealingKey, Bytes),
    Open(OpeningKey, Bytes),
}

pub struct RingAeadCipher {
    cryptor: RingAeadCryptor,
    method: CipherMethod,
    secret_key: Bytes,
    nonce: BytesMut,
    tag_len: usize,
}

impl RingAeadCipher {
    pub fn new(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8], is_seal: bool) -> Self {
        let nonce_len = method.nonce_len();
        let mut nonce = BytesMut::with_capacity(nonce_len);
        unsafe {
            nonce.set_len(nonce_len);
            ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_len);
        }

        let secret_key = method.make_secret_key(key_derive_from_pass, salt);
        let cryptor = RingAeadCipher::new_cryptor(method, &secret_key, &nonce, is_seal);
        let tag_len = method.tag_len();

        RingAeadCipher {
            cryptor,
            method,
            secret_key,
            nonce,
            tag_len,
        }
    }

    fn new_cryptor(m: CipherMethod, key: &Bytes, in_nonce: &[u8], is_seal: bool) -> RingAeadCryptor {
        let nonce = Bytes::from(in_nonce);
        let cryptor = match m {
            Aes256Gcm => {
                if is_seal {
                    RingAeadCryptor::Seal(SealingKey::new(&AES_256_GCM, &key).unwrap(), nonce)
                } else {
                    RingAeadCryptor::Open(OpeningKey::new(&AES_256_GCM, &key).unwrap(), nonce)
                }
            }

            Chacha20IetfPoly1305 => {
                if is_seal {
                    RingAeadCryptor::Seal(SealingKey::new(&CHACHA20_POLY1305, &key).unwrap(), nonce)
                } else {
                    RingAeadCryptor::Open(OpeningKey::new(&CHACHA20_POLY1305, &key).unwrap(), nonce)
                }
            }

            _ => unimplemented!(),
        };

        cryptor
    }

    fn do_decrypt(&mut self, openbuf: &mut [u8], out: &mut [u8]) -> io::Result<()> {
        debug_assert_eq!(out.len(), openbuf.len() - self.tag_len);
        let rlt = {
            if let RingAeadCryptor::Open(ref key, ref nonce) = self.cryptor {
                match open_in_place(
                    key,
                    Nonce::try_assume_unique_for_key(nonce).unwrap(),
                    Aad::empty(),
                    0,
                    openbuf,
                ) {
                    Ok(text) => {
                        out.copy_from_slice(text);
                        Ok(())
                    }

                    Err(e) => {
                        error!(
                            "AEAD decrypt failed, nonce={:?}, tag={:?}, err={:?}",
                            ByteStr::new(nonce.as_ref()),
                            ByteStr::new(&openbuf[..self.tag_len]),
                            e
                        );

                        Err(Error::new(ErrorKind::Other, "aead decrypt failed"))
                    }
                }
            } else {
                unreachable!("decrypt called on a non-open cipher");
            }
        };

        self.increse_nonce();

        rlt
    }

    fn increse_nonce(&mut self) {
        increment_le(&mut self.nonce);

        let is_seal = match self.cryptor {
            RingAeadCryptor::Seal(..) => true,
            RingAeadCryptor::Open(..) => false,
        };

        let cryptor = RingAeadCipher::new_cryptor(self.method, &self.secret_key, &self.nonce, is_seal);
        std::mem::replace(&mut self.cryptor, cryptor);
    }
}

impl AeadDecryptor for RingAeadCipher {
    fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> io::Result<()> {
        if ciphertext.len() <= SS_TCP_CHUNK_LEN {
            let mut buf = [0u8; SS_TCP_CHUNK_LEN];
            &mut buf[..ciphertext.len()].copy_from_slice(&ciphertext[..]);
            self.do_decrypt(&mut buf[..ciphertext.len()], plaintext)
        } else {
            let mut buf = BytesMut::with_capacity(ciphertext.len());
            buf.put_slice(ciphertext);
            self.do_decrypt(&mut buf, plaintext)
        }
    }
}

impl AeadEncryptor for RingAeadCipher {
    fn encrypt(&mut self, in_out: &mut [u8]) -> io::Result<()> {
        let rlt = {
            if let RingAeadCryptor::Seal(ref key, ref nonce) = self.cryptor {
                match seal_in_place(
                    key,
                    Nonce::try_assume_unique_for_key(nonce).unwrap(),
                    Aad::empty(),
                    in_out,
                    self.tag_len,
                ) {
                    Ok(_) => Ok(()),

                    Err(_) => {
                        error!("aead encrypt failed");

                        Err(Error::new(ErrorKind::Other, "aead encrypt failed"))
                    }
                }
            } else {
                unreachable!("encrypt called on a non-seal cipher");
            }
        };

        self.increse_nonce();

        rlt
    }
}
