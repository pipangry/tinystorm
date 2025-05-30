use crate::cipher::CHUNK_SIZE;
use crate::error::CipherError;

/// Check if the new key has the correct form.
/// Returns true if form is correct
#[inline]
pub(crate) fn verify_key(key: &[u8]) -> bool {
    if key.len() != CHUNK_SIZE {
        return false;
    }
    true
}

/// Credentials of the cipher: Key and IV
#[derive(Debug, PartialEq)]
pub struct Credentials {
    pub(crate) key: Vec<u8>,
    pub(crate) iv: u8,
}

impl Credentials {
    pub fn new(key: &[u8], iv: u8) -> Self {
        Self {
            key: key.to_vec(),
            iv,
        }
    }

    /// Verify if IV and key parts don't exceed the encoding size which can lead to
    /// decryption problems
    pub(crate) fn verify_credentials_size(&self, encoding_range: u8) -> Result<(), CipherError> {
        if let Some(b) = self.key.iter().find(|&b| *b >= encoding_range) {
            return Err(CipherError::KeyOutOfBounds(*b))
        }
        
        if self.iv >= encoding_range {
            return Err(CipherError::IVOutOfBounds);
        }
        
        Ok(())
    }

    /// Expand single key to multiple keys for each chunk
    /// `size` - amount of chunks you have to expand the key
    /// # Example
    /// ```
    /// use tinystorm::cipher::CHUNK_SIZE;
    /// use tinystorm::key::Credentials;
    /// // 4 Chunks
    /// let size = 4;
    ///
    /// // The size is how many chunks we have, so we can predict the required space
    /// let mut buffer = Vec::with_capacity(CHUNK_SIZE * size);
    /// let credentials = Credentials::new(&[1, 2, 3, 4], 27);
    /// // range_mod is modulus for finite field operations in key expansion,
    /// // set it to size of your encoding table (.len())
    /// credentials.expand_key(&mut buffer, size, 41);
    ///
    /// println!("{:?}", buffer);
    /// // [1, 2, 3, 4, 31, 17, 3, 30, 16, 2, 29, 15, 1, 28, 14, 0]
    /// ```
    pub fn expand_key(&self, buffer: &mut Vec<u8>, size: usize, range_mod: u8) {
        buffer.clear();

        // Pushing initial key to buffer as first key
        buffer.append(&mut self.key.clone());

        // If size is only one chunk, we don't need to expand it anymore
        if size <= 1 {
            return;
        }

        while buffer.len() < size * CHUNK_SIZE {
            // First step: Apply IV
            let mut key_with_iv = buffer
                .last()
                .iter()
                .map(|&c| (c + self.iv) % range_mod)
                .collect::<Vec<u8>>();

            // Second step: Swap
            swap_key(&mut key_with_iv, range_mod);

            buffer.append(&mut key_with_iv);
        }
    }
}

/// Convert and verify credentials from strings
pub(crate) fn parse_credentials<'a>(key: &'a str, iv: &'a str) -> Result<Credentials, CipherError> {
    let mut parsed_key: Vec<u8> = Vec::with_capacity(CHUNK_SIZE);

    let key_as_chars = key.chars().collect::<Vec<_>>();
    let key_as_chunks = key_as_chars.chunks(2);

    for chunk in key_as_chunks {
        let glued_chunk = chunk.iter().collect::<String>();

        let key_chunks_as_u8 = glued_chunk
            .parse::<u8>()
            .map_err(CipherError::ParseIntError)?;
        parsed_key.push(key_chunks_as_u8);
    }

    // The same logic as in `verify_key` function
    if parsed_key.len() != CHUNK_SIZE {
        return Err(CipherError::InvalidKey);
    }

    let iv_as_u8 = iv.parse::<u8>().map_err(CipherError::ParseIntError)?;

    Ok(Credentials {
        key: parsed_key,
        iv: iv_as_u8,
    })
}

/// Helper function for `extend_key`
/// Has slightly different logic from regular chunk swap
pub(crate) fn swap_key(buffer: &mut [u8], range_mod: u8) {
    if buffer.len() < CHUNK_SIZE {
        return;
    }

    let [a, b, c, d] = [buffer[0], buffer[1], buffer[2], buffer[3]];

    buffer[0] = (a + b) % range_mod;
    buffer[1] = (buffer[0] + c) % range_mod;
    buffer[2] = (c + d) % range_mod;
    buffer[3] = (buffer[2] + b) % range_mod;
}