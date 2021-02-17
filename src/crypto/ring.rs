use super::cipher::CipherMethod::{self, *};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};

use super::aead::{AeadDecryptor, AeadEncryptor};
use byte_string::ByteStr;
use bytes::{Bytes, BytesMut};
use log::error;
use sodiumoxide::utils::increment_le;
use std::{
    io::{self, Error, ErrorKind},
    ptr,
};

pub struct RingAeadCipher {
    cryptor: LessSafeKey,
    nonce: BytesMut,
    tag_len: usize,
}

impl RingAeadCipher {
    pub fn new(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> Self {
        let nonce_len = method.nonce_len();
        let mut nonce = BytesMut::with_capacity(nonce_len);
        unsafe {
            nonce.set_len(nonce_len);
            ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_len);
        }

        let secret_key = method.make_secret_key(key_derive_from_pass, salt);
        let cryptor = RingAeadCipher::new_cryptor(method, &secret_key);
        let tag_len = method.tag_len();

        RingAeadCipher {
            cryptor,
            nonce,
            tag_len,
        }
    }

    fn new_cryptor(m: CipherMethod, key: &Bytes) -> LessSafeKey {
        let unbound_key = match m {
            Aes256Gcm => {
                assert_eq!(key.len(), AES_256_GCM.key_len());

                UnboundKey::new(&AES_256_GCM, &key).unwrap()
            }

            Chacha20IetfPoly1305 => {
                assert_eq!(key.len(), CHACHA20_POLY1305.key_len());

                UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap()
            }

            _ => unimplemented!(),
        };

        LessSafeKey::new(unbound_key)
    }

    fn increse_nonce(&mut self) {
        increment_le(&mut self.nonce);
    }
}

impl AeadDecryptor for RingAeadCipher {
    fn decrypt(&mut self, in_out: &mut [u8]) -> io::Result<()> {
        let rlt = {
            match self.cryptor.open_in_place(
                Nonce::try_assume_unique_for_key(&self.nonce).unwrap(),
                Aad::empty(),
                in_out,
            ) {
                Ok(_) => Ok(()),

                Err(e) => {
                    error!(
                        "AEAD decrypt failed, nonce={:?}, tag={:?}, err={:?}",
                        ByteStr::new(self.nonce.as_ref()),
                        ByteStr::new(&in_out[..self.tag_len]),
                        e
                    );

                    Err(Error::new(ErrorKind::Other, "aead decrypt failed"))
                }
            }
        };

        self.increse_nonce();

        rlt
    }
}

impl AeadEncryptor for RingAeadCipher {
    fn encrypt(&mut self, in_out: &mut [u8]) -> io::Result<()> {
        let (cipher_in_plain_out, tag) = in_out.split_at_mut(in_out.len() - self.tag_len);
        let rlt = {
            match self.cryptor.seal_in_place_separate_tag(
                Nonce::try_assume_unique_for_key(&self.nonce).unwrap(),
                Aad::empty(),
                cipher_in_plain_out,
            ) {
                Ok(tag_out) => {
                    tag.copy_from_slice(tag_out.as_ref());
                    Ok(())
                }

                Err(_) => {
                    error!("aead encrypt failed");

                    Err(Error::new(ErrorKind::Other, "aead encrypt failed"))
                }
            }
        };

        self.increse_nonce();

        rlt
    }
}
