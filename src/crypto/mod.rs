pub mod aead;
pub mod cipher;

#[cfg(feature = "cipher-crypto2")]
mod crypto2;
#[cfg(feature = "cipher-ring")]
mod ring;

use aead::{AeadDecryptor, AeadEncryptor};
use cipher::CipherMethod::{self, *};
use std::boxed::Box;

#[cfg(feature = "cipher-crypto2")]
use self::crypto2::Crypto2AeadCipher;
#[cfg(feature = "cipher-ring")]
use self::ring::RingAeadCipher;

pub type BoxAeadDecryptor = Box<dyn AeadDecryptor + std::marker::Send + 'static>;
pub type BoxAeadEncryptor = Box<dyn AeadEncryptor + std::marker::Send + 'static>;

pub fn new_aead_decryptor(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> BoxAeadDecryptor {
    match method {
        #[cfg(feature = "cipher-crypto2")]
        Aes256Gcm | Chacha20IetfPoly1305 => Box::new(Crypto2AeadCipher::new(method, key_derive_from_pass, salt)),
        #[cfg(feature = "cipher-ring")]
        Aes256Gcm | Chacha20IetfPoly1305 => Box::new(RingAeadCipher::new(method, key_derive_from_pass, salt)),
    }
}

pub fn new_aead_encryptor(method: CipherMethod, key_derive_from_pass: &[u8], salt: &[u8]) -> BoxAeadEncryptor {
    match method {
        #[cfg(feature = "cipher-crypto2")]
        Aes256Gcm | Chacha20IetfPoly1305 => Box::new(Crypto2AeadCipher::new(method, key_derive_from_pass, salt)),
        #[cfg(feature = "cipher-ring")]
        Aes256Gcm | Chacha20IetfPoly1305 => Box::new(RingAeadCipher::new(method, key_derive_from_pass, salt)),
    }
}
