use super::{
    aead::{AeadDecryptor, AeadEncryptor},
    cipher::CipherMethod,
};
use byte_string::ByteStr;
use bytes::{Bytes, BytesMut};
use crypto2::{
    aeadcipher::{AeadCipher, Chacha20Poly1305},
    blockmode,
};
use log::error;
use sodiumoxide::utils::increment_le;
use std::io::{self, Error, ErrorKind};

enum Crypto2Cipher {
    Aes(blockmode::Aes256Gcm),
    Chacha20(Chacha20Poly1305),
}

pub struct Crypto2AeadCipher {
    cipher: Crypto2Cipher,
    nonce: BytesMut,
    tag_len: usize,
}

impl Crypto2AeadCipher {
    pub fn new(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> Self {
        let secret_key = method.make_secret_key(key_derive_from_pass, salt);
        let cipher = Crypto2AeadCipher::new_cryptor(method, &secret_key);

        Crypto2AeadCipher {
            cipher,
            nonce: method.nonce(),
            tag_len: method.tag_len(),
        }
    }

    fn new_cryptor(m: CipherMethod, key: &Bytes) -> Crypto2Cipher {
        let cipher = match m {
            CipherMethod::Aes256Gcm => Crypto2Cipher::Aes(blockmode::Aes256Gcm::aead_new(key)),

            CipherMethod::Chacha20IetfPoly1305 => Crypto2Cipher::Chacha20(Chacha20Poly1305::aead_new(key)),

            _ => unimplemented!(),
        };

        cipher
    }

    fn increse_nonce(&mut self) {
        increment_le(&mut self.nonce);
    }
}

impl AeadDecryptor for Crypto2AeadCipher {
    fn decrypt(&mut self, in_out: &mut [u8]) -> io::Result<()> {
        let aad = [0u8; 0];
        let (cipher_in_plain_out, tag) = in_out.split_at_mut(in_out.len() - self.tag_len);
        let done: bool = {
            match self.cipher {
                Crypto2Cipher::Aes(ref aes) => {
                    aes.aead_decrypt_slice_detached(&self.nonce, &aad, cipher_in_plain_out, tag)
                }

                Crypto2Cipher::Chacha20(ref chacha) => {
                    chacha.aead_decrypt_slice_detached(&self.nonce, &aad, cipher_in_plain_out, tag)
                }
            }
        };
        if done == false {
            error!(
                "AEAD decrypt failed, nonce={:?}, tag = {:?}",
                ByteStr::new(self.nonce.as_ref()),
                ByteStr::new(tag)
            );

            return Err(Error::new(ErrorKind::Other, "aead decrypt failed"));
        }

        self.increse_nonce();

        Ok(())
    }
}

impl AeadEncryptor for Crypto2AeadCipher {
    fn encrypt(&mut self, in_out: &mut [u8]) -> io::Result<()> {
        let aad = [0u8; 0];
        let (plain_in_cipher_out, tag) = in_out.split_at_mut(in_out.len() - self.tag_len);
        match self.cipher {
            Crypto2Cipher::Aes(ref aes) => {
                aes.aead_encrypt_slice_detached(&self.nonce, &aad, plain_in_cipher_out, tag);
            }

            Crypto2Cipher::Chacha20(ref chacha) => {
                chacha.aead_encrypt_slice_detached(&self.nonce, &aad, plain_in_cipher_out, tag);
            }
        }

        self.increse_nonce();

        Ok(())
    }
}
