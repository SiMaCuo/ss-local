mod buf;
pub mod copy_into;
pub mod crypto_io;
pub mod socks5;
pub mod timeout;

pub const KB: usize = 1024;
pub const ENC_CHUNK_LEN: usize = 13*KB;
