use super::{
    aead::{AeadDecryptor, AeadEncryptor},
    cipher::CipherMethod,
};
use bytes::BytesMut;
use log::error;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::*;
use std::{
    io::{self, Error, ErrorKind},
    ptr,
};

#[allow(dead_code)]
pub struct SodiumAeadCipher {
    method: CipherMethod,
    secret_key: Key,
    nonce: Nonce,
    tag_len: usize,
}

impl SodiumAeadCipher {
    pub fn new(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> SodiumAeadCipher {
        match method {
            CipherMethod::XChacha20IetfPoly1305 => {
                let nonce_len = method.nonce_len();
                let mut nonce = BytesMut::with_capacity(nonce_len);
                unsafe {
                    nonce.set_len(nonce_len);
                    ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_len);
                }

                let secret_key = Key::from_slice(&method.make_secret_key(&key_derive_from_pass, &salt)).unwrap();
                let tag_len = method.tag_len();
                SodiumAeadCipher {
                    method,
                    secret_key,
                    nonce: Nonce::from_slice(&nonce).unwrap(),
                    tag_len,
                }
            }

            _ => unimplemented!(),
        }
    }

    fn increse_nonce(&mut self) {
        self.nonce.increment_le_inplace();
    }
}

impl AeadDecryptor for SodiumAeadCipher {
    fn decrypt(&mut self, in_out: &mut [u8]) -> io::Result<()> {
        let rlt = {
            let mid = in_out.len() - self.tag_len;
            let (c, tag) = in_out.split_at_mut(mid);
            if let Ok(_) = open_detached(
                c,
                None,
                Tag::from_slice(tag).as_ref().unwrap(),
                &self.nonce,
                &self.secret_key,
            ) {
                Ok(())
            } else {
                error!(
                    "sodium aead decrypt failed. nonce={:?}, key={:?}",
                    self.nonce, self.secret_key
                );

                Err(Error::new(ErrorKind::Other, "sodium aead decrypt failed"))
            }
        };

        self.increse_nonce();

        rlt
    }
}

impl AeadEncryptor for SodiumAeadCipher {
    fn encrypt(&mut self, in_out: &mut [u8]) -> io::Result<()> {
        let plaintext_len = in_out.len() - self.tag_len;
        let tag = seal_detached(&mut in_out[..plaintext_len], None, &self.nonce, &self.secret_key);

        &mut in_out[plaintext_len..plaintext_len + self.tag_len].copy_from_slice(&tag[..]);
        self.increse_nonce();

        Ok(())
    }
}
