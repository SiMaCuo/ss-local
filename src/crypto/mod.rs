pub mod aead;
pub mod cipher;
mod ring;

use aead::{AeadDecryptor, AeadEncryptor};
use cipher::CipherMethod::{self, *};
use std::boxed::Box;
use self::ring::RingAeadCipher;

pub type BoxAeadDecryptor = Box<dyn AeadDecryptor + std::marker::Send + 'static>;
pub type BoxAeadEncryptor = Box<dyn AeadEncryptor + std::marker::Send + 'static>;

pub fn new_aead_decryptor(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> BoxAeadDecryptor {
    match method {
        Aes256Gcm | Chacha20IetfPoly1305 => Box::new(RingAeadCipher::new(method, key_derive_from_pass, salt)),
    }
}

pub fn new_aead_encryptor(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> BoxAeadEncryptor {
    match method {
        Aes256Gcm | Chacha20IetfPoly1305 => Box::new(RingAeadCipher::new(method, key_derive_from_pass, salt)),
    }
}
