use crate::encoding::{Encoder, EncodingType, DEFAULT_ENCODING};
use crate::error::CipherError;
use crate::key::{parse_credentials, verify_key, Credentials};

pub const CHUNK_SIZE: usize = 4;

#[derive(Debug)]
pub struct Cipher {
    encoder: Encoder,
    credentials: Credentials,
}

impl Cipher {
    pub fn new(key: &[u8], iv: u8) -> Result<Cipher, CipherError> {
        if !verify_key(key) {
            return Err(CipherError::InvalidKey);
        }
        
        Ok(
            Cipher {
                encoder: Encoder::new(DEFAULT_ENCODING),
                credentials: Credentials {
                    key: key.to_vec(),
                    iv
                }
            }
        )
    }
    
    /// Parse credentials as strings and create new Cipher
    pub fn from(key: &str, iv: &str) -> Result<Cipher, CipherError> {
        let credentials = parse_credentials(key, iv)?;
        
        Ok(
            Cipher {
                encoder: Encoder::new(DEFAULT_ENCODING),
                credentials,
            }
        )
    }
    
    /// Change encoding (ENv1) to other
    /// # Example
    /// ```
    /// use tinystorm::cipher::Cipher;
    /// use tinystorm::encoding::EncodingType;
    /// 
    /// let cipher = Cipher::from("23091234", "89")
    ///     .unwrap()
    ///     .set_encoder(EncodingType::RUv5);
    /// ```
    pub fn set_encoder(&mut self, encoding_type: EncodingType) {
        self.encoder = Encoder::new(encoding_type);
    }
    
    /// Change encoding to your custom one
    pub fn load_encoder(
        &mut self,
        table: &'static [(char, u8)],
        supports_uppercase: bool,
    ) -> Result<(), CipherError> {
        self.encoder = Encoder::load(table, supports_uppercase)?;
        Ok(())
    }
}

