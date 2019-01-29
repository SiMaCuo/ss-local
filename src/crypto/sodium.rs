use aead::{AeadDecryptor, AeadEncryptor};
use cipher::{self, CipherMethod::*};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::*;
use std::{ptr, io};

struct SodiumAeadCipher {
    method: CipherMethod,
    secret_key: Key,
    nonce: Nonce,
    tag_len: usize,
}

impl SodiumAeadCipher {
    fn new(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> SodiumAeadCipher {
        match method {
            CipherMethod::XChacha20IetfPoly1305 => {
                let nonce_len = method.nonce_len();
                let mut nonce = BytesMut::with_capacity(nonce_len);
                unsafe {
                    nonce.set_len(nonce_len);
                    ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_len);
                }

                let secret_key = Key::from_slice(&method.make_subkey(&key_derive_from_pass, &salt)).unwrap();
                let tag_len = method.tag_len();
                SodiumAeadCipher {
                    method,
                    secret_key,
                    nonce: Nonce::from_slice(&nonce),
                    tag_len,
                }
            }

            _ => unimplmented!(),
        }
    }

    fn increse_nonce(&mut self) {
        self.nonce.increment_le_inplace();
    }
}

impl AeadDecryptor for SodiumAeadCipher {
    fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> io::Result<()> {
        debug_assert_eq!(ciphertext.len() - self.tag_len, plaintext.len());

        let rlt = if let Ok(v) = open(ciphertext, None, self.nonce, self.secret_key) {
            debug_assert_eq!(plaintext.len(), v.len());

            plaintext.copy_from_slice(&v);

            Ok(())
        } else {
            error!("sodium aead decrypt failed. nonce={:?}, key={:?}",
                   ByteStr(self.nonce.as_ref()),
                   ByteStr(self.secret_key.as_ref()));

            Err(Error::new(ErrorKind::Other, "sodium aead decrypt failed"))
        }
        
        self.increse_nonce();
    }
}

impl AeadEncryptor for SodiumAeadCipher {
    fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> io::Result<()> {
        debug_assert_eq!(self.tag_len + plaintext.len(), ciphertext.len());

        let v = seal(plaintext, None, &self.Nonce, &self.secret_key);
        debug_assert_eq!(v.len(), ciphertext.len());

        ciphertext.copy_from_slice(&v);
        self.increse_nonce();

        Ok(())
    }
}

                   


