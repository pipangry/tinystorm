#[derive(Debug)]
pub enum CipherError {
    InvalidKey,
    InvalidIV,
    ParseIntError(std::num::ParseIntError),
    MalformedEncoding,
}