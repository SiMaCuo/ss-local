pub mod aead;
pub mod cipher;
mod ring;
mod sodium;

use self::ring::RingAeadCipher;
use aead::{AeadDecryptor, AeadEncryptor};
use cipher::CipherMethod::{self, *};
use sodium::SodiumAeadCipher;
use std::boxed::Box;

pub fn new_aead_decryptor(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> Box<AeadDecryptor> {
    match method {
        Aes256Gcm | Chacha20IetfPoly1305 => box RingAeadCipher::new(method, key_derive_from_pass, salt, false),

        XChacha20IetfPoly1305 => box SodiumAeadCipher::new(method, key_derive_from_pass, salt),
    }
}

pub fn new_aead_encryptor(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> Box<AeadEncryptor> {
    match method {
        Aes256Gcm | Chacha20IetfPoly1305 => box RingAeadCipher::new(method, key_derive_from_pass, salt, true),

        XChacha20IetfPoly1305 => box SodiumAeadCipher::new(method, key_derive_from_pass, salt),
    }
}
