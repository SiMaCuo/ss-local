#[cfg(feature = "cipher-crypto2")]
use crypto2::{
    aeadcipher::{AeadCipher, Chacha20Poly1305},
    blockmode::Aes256Gcm,
    kdf::HkdfSha1,
};

#[cfg(feature = "cipher-ring")]
use ring::{
    aead::{self, AES_256_GCM, CHACHA20_POLY1305},
    hkdf,
};

use bytes::{BufMut, Bytes, BytesMut};
use rand::{self, RngCore};
use std::{
    io::{Error, ErrorKind},
    str::FromStr,
};

const CIPHER_AES_256_GCM: &str = "aes-256-gcm";
const CIPHER_CHACHA20_IETF_POLY1305: &str = "chacha20-ietf-poly1305";

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum CipherMethod {
    Aes256Gcm,
    Chacha20IetfPoly1305,
}

impl CipherMethod {
    pub fn key_len(&self) -> usize {
        #[cfg(feature = "cipher-crypto2")]
        match self {
            CipherMethod::Aes256Gcm => Aes256Gcm::aead_key_len(),
            CipherMethod::Chacha20IetfPoly1305 => Chacha20Poly1305::aead_key_len(),
        }

        #[cfg(feature = "cipher-ring")]
        match self {
            CipherMethod::Aes256Gcm => AES_256_GCM.key_len(),
            CipherMethod::Chacha20IetfPoly1305 => CHACHA20_POLY1305.key_len(),
        }
    }

    pub fn tag_len(&self) -> usize {
        #[cfg(feature = "cipher-crypto2")]
        match self {
            CipherMethod::Aes256Gcm => Aes256Gcm::aead_tag_len(),
            CipherMethod::Chacha20IetfPoly1305 => Chacha20Poly1305::aead_tag_len(),
        }

        #[cfg(feature = "cipher-ring")]
        match self {
            CipherMethod::Aes256Gcm => AES_256_GCM.tag_len(),
            CipherMethod::Chacha20IetfPoly1305 => CHACHA20_POLY1305.tag_len(),
        }
    }

    pub fn nonce(&self) -> BytesMut {
        match self {
            CipherMethod::Aes256Gcm | CipherMethod::Chacha20IetfPoly1305 => {
                #[cfg(feature = "cipher-crypto2")]
                {
                    assert_eq!(Aes256Gcm::NONCE_LEN, Chacha20Poly1305::NONCE_LEN);
                    let mut nonce = BytesMut::with_capacity(Aes256Gcm::NONCE_LEN);
                    nonce.put(&[0u8; Aes256Gcm::NONCE_LEN][..]);
                    nonce
                }

                #[cfg(feature = "cipher-ring")]
                {
                    let mut nonce = BytesMut::with_capacity(aead::NONCE_LEN);
                    nonce.put(&[0u8; aead::NONCE_LEN][..]);
                    nonce
                }
            }
        }
    }

    pub fn derive_key(password: &[u8], key_len: usize) -> Bytes {
        debug_assert!(key_len > 0);
        let mut key = BytesMut::with_capacity(key_len);
        unsafe {
            key.set_len(key_len);
        }
        #[cfg(feature = "cipher-crypto2")]
        {
            HkdfSha1::oneshot(&[0u8; 0][..], password, &[0u8; 0][..], &mut key);
        }

        #[cfg(feature = "cipher-ring")]
        {
            hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, &[])
                .extract(password)
                .expand(&[], &AES_256_GCM)
                .unwrap()
                .fill(&mut key)
                .unwrap();
        }
        key.freeze()
    }

    pub fn make_secret_key(&self, key: &[u8], salt: &[u8]) -> Bytes {
        let key_len = self.key_len();
        let mut skey = BytesMut::with_capacity(key_len);
        unsafe {
            skey.set_len(key_len);
        }

        #[cfg(feature = "cipher-crypto2")]
        {
            HkdfSha1::oneshot(salt, key, b"ss-subkey", &mut skey);
        }

        #[cfg(feature = "cipher-ring")]
        {
            hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
                .extract(key)
                .expand(&[b"ss-subkey"], &AES_256_GCM)
                .unwrap()
                .fill(&mut skey)
                .unwrap()
        }
        skey.freeze()
    }

    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    pub fn gen_salt(&self) -> Bytes {
        let salt_len = self.salt_len();
        let mut salt = BytesMut::with_capacity(salt_len);
        unsafe {
            salt.set_len(salt_len);
        }

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);

        salt.freeze()
    }
}

impl FromStr for CipherMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<CipherMethod, Error> {
        match s {
            CIPHER_AES_256_GCM => Ok(CipherMethod::Aes256Gcm),
            CIPHER_CHACHA20_IETF_POLY1305 => Ok(CipherMethod::Chacha20IetfPoly1305),
            _ => Err(Error::new(ErrorKind::Other, "unknown cipher method")),
        }
    }
}
