use std::io;

pub trait AeadDecryptor {
    fn decrypt(&mut self, cipertext: &[u8], plaintext: &mut [u8]) -> io::Result<()>;
}

pub trait AeadEncryptor {
    fn encrypt(&mut self, plaintext: &[u8], cipertext: &mut [u8]) -> io::Result<()>;
}
