#[derive(Debug, PartialEq)]
pub enum CipherError {
    InvalidKey,
    InvalidIV,
    ParseIntError(std::num::ParseIntError),
    MalformedEncoding,
    IVOutOfBounds,
    KeyOutOfBounds(u8),
}
