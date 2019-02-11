mod buf;
pub mod copy_into;
pub mod crypto_io;
pub mod socks5;


// ppoe connection mtu seem to be 1492, ip header 20, tcp header 20
pub const SS_TCP_CHUNK_LEN: usize = 1452;
