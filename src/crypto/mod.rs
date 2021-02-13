pub mod aead;
pub mod cipher;
mod sodium;
mod crypto2;

use self::crypto2::Crypto2AeadCipher;
use aead::{AeadDecryptor, AeadEncryptor};
use cipher::CipherMethod::{self, *};
use sodium::SodiumAeadCipher;
use std::boxed::Box;

pub type BoxAeadDecryptor = Box<dyn AeadDecryptor + std::marker::Send + 'static>;
pub type BoxAeadEncryptor = Box<dyn AeadEncryptor + std::marker::Send + 'static>;

pub fn new_aead_decryptor(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> BoxAeadDecryptor {
    match method {
        Aes256Gcm | Chacha20IetfPoly1305 => box Crypto2AeadCipher::new(method, key_derive_from_pass, salt),

        XChacha20IetfPoly1305 => box SodiumAeadCipher::new(method, key_derive_from_pass, salt),
    }
}

pub fn new_aead_encryptor(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> BoxAeadEncryptor {
    match method {
        Aes256Gcm | Chacha20IetfPoly1305 => box Crypto2AeadCipher::new(method, key_derive_from_pass, salt),

        XChacha20IetfPoly1305 => box SodiumAeadCipher::new(method, key_derive_from_pass, salt),
    }
}
