use std::error::Error;
use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub enum CipherError {
    InvalidKey,
    InvalidIV,
    ParseIntError(std::num::ParseIntError),
    MalformedEncoding,
    IVOutOfBounds(u8),
    KeyOutOfBounds(u8, u8),
}

impl Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CipherError::InvalidKey => write!(f, "Invalid Key"),
            CipherError::InvalidIV => write!(f, "Invalid IV"),
            CipherError::ParseIntError(e) => write!(f, "{e}"),
            CipherError::MalformedEncoding => {
                write!(f, "Malformed encoding: each character must me unique")
            }
            CipherError::IVOutOfBounds(bounds) => write!(f, "IV must be within {bounds}"),
            CipherError::KeyOutOfBounds(chunk, bounds) => {
                write!(f, "Key chunk {chunk} out of bounds: {bounds}")
            }
        }
    }
}

impl Error for CipherError {}
