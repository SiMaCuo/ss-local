use std::io;

pub trait AeadDecryptor {
    fn decrypt(&mut self, in_out: &mut [u8]) -> io::Result<()>;
}

pub trait AeadEncryptor {
    fn encrypt(&mut self, in_out: &mut [u8]) -> io::Result<()>;
}
