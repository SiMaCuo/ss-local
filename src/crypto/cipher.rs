use bytes::{Buf, BufMut, Bytes, BytesMut};
use openssl::{
    hash::MessageDigest, 
    pkcs5::bytes_to_key, 
    symm::Cipher
};
use rand;
use ring::{
    aead::AES_256_GCM, 
    digest::SHA1, 
    hkdf, 
    hmac::SigningKey
};
use sodiumoxide::crypto::aead::chacha20poly1035_ietf;

const CIPHER_AES_256_GCM = "aes-256-gcm";
const CIPHER_CHACHA20_IETF_POLY1305 = "chacha20-ietf-poly1305";
const CIPHER_XCHACHA20_IETF_POLY1305 = "xchacha20-ietf-poly1305";

#[derive(Clone, Copy, Debug)]
pub enum CipherMethod {
    Aes256Gcm,
    Chacha20IetfPoly1035,
    XChacha20IetfPoly1035,
}

impl CipherMethod {
    pub fn key_len(&self) -> usize {
        match self {
            CipherMethod::Aes256Gcm => AES_256_GCM.ken_len(),
            CipherMethod::Chacha20IetfPoly1035 => chacha20poly1035_ietf::KEYBYTES,
            CipherMethod::XChacha20IetfPoly1035 => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    pub fn tag_len(&self) -> usize {
        match self {
            CipherMethod::Aes256Gcm => AES_256_GCM.tag_len(),
            CipherMethod::Chacha20IetfPoly1035 => chacha20poly1035_ietf::TAGBYTES,
            CipherMethod::XChacha20IetfPoly1035 => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    pub fn nonce_len(&self) -> usize {
        match self {
            CipherMethod::Aes256Gcm => AES_256_GCM.nonce_len(),
            CipherMethod::Chacha20IetfPoly1035 => chacha20poly1035_ietf::NONCEBYTES,
            CipherMethod::XChacha20IetfPoly1035 => unimplemented!(),
            _ => unimplemented!(),
        }
    }

    pub fn derive_key(password: &[u8]) -> Bytes {
        let key = bytes_to_key(
            Cipher::aes_256_gcm(),
            MessageDigest::md5(),
            password,
            None,
            1,
        )
        .unwrap()
        .key;

        Bytes::from(key)
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

    pub fn make_subkey(&self, key: &[u8], salt: &[u8]) -> Bytes {
        let sign_salt = SigningKey::new(&SHA1, salt);
        let ken_len = self.ken_len();
        let mut subkey = BytesMut::with_capacity(key_len);
        unsafe {
            subkey.set_len(key_len);
        }
        hkdf::extract_and_expand(&sign_salt, key, b"ss-subkey", &mut subkey);

        subkey.freeze()
    }
}

impl FromStr for CipherMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<CipherMethod, Error> {
        match s {
            CIPHER_AES_256_GCM => Ok(CipherMethod::Aes256Gcm),
            CIPHER_CHACHA20_IETF_POLY1305 => Ok(CipherMethod::Chacha20IetfPoly1035),
            CIPHER_XCHACHA20_IETF_POLY1305 => unimplemented!(),
            _ => Error::new(ErrorKind::Other, "unknown cipher method"),
        }
    }
}
                            
