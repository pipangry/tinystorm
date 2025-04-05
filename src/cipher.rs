use crate::encoding::{DEFAULT_ENCODING, Encoder, EncodingType};
use crate::error::CipherError;
use crate::key::{Credentials, parse_credentials, verify_key};

pub const CHUNK_SIZE: usize = 4;

#[derive(Debug, PartialEq)]
pub struct Cipher {
    encoder: Encoder,
    credentials: Credentials,
}

impl Cipher {
    /// Create new Cipher from raw key and IV with default ENv1 encoding
    pub fn new(key: &[u8], iv: u8) -> Result<Cipher, CipherError> {
        if !verify_key(key) {
            return Err(CipherError::InvalidKey);
        }

        Ok(Cipher {
            encoder: Encoder::new(DEFAULT_ENCODING),
            credentials: Credentials {
                key: key.to_vec(),
                iv,
            },
        })
    }

    /// Parse credentials as strings and create new Cipher
    /// # Example
    /// ```
    /// use tinystorm::cipher::Cipher;
    ///
    /// let cipher = Cipher::from("23091234", "89")
    ///     .unwrap();
    /// ```
    pub fn from(key: &str, iv: &str) -> Result<Cipher, CipherError> {
        let credentials = parse_credentials(key, iv)?;

        Ok(Cipher {
            encoder: Encoder::new(DEFAULT_ENCODING),
            credentials,
        })
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
    /// # Example
    /// ```
    /// use tinystorm::cipher::Cipher;
    /// use tinystorm::encoding::Encoding;
    ///
    /// const MY_TABLE: Encoding = &[
    ///     ('a', 1),
    ///     ('b', 2),
    ///     ('c', 3),
    /// ];
    ///
    /// let cipher = Cipher::new(&[1, 2, 3, 4], 5)
    ///     .unwrap()
    ///     .load_encoder(MY_TABLE, false);
    /// ```
    pub fn load_encoder(
        &mut self,
        table: &'static [(char, u8)],
        supports_uppercase: bool,
    ) -> Result<(), CipherError> {
        self.encoder = Encoder::load(table, supports_uppercase)?;
        Ok(())
    }

    /// Raw encryption function.
    /// Warning! If your buffer is can't be divided by CHUNK_SIZE without
    /// remainder, it can be truncated. Not recommended to use
    pub fn encrypt_raw(&self, buffer: &mut [u8]) {
        let chunks = buffer.chunks_exact_mut(CHUNK_SIZE);

        // Expanding key
        let key_capacity = chunks.len();
        let mut key = Vec::with_capacity(key_capacity);
        self.credentials.expand_key(&mut key, key_capacity, self.encoder.size);

        // Swap chunks
        for chunk in chunks {
            swap_chunk(chunk, self.encoder.size)
        }

        // Add key
        for (d, s) in buffer.iter_mut().zip(key.iter()) {
            *d = (*d + *s) % self.encoder.size;
        }
    }

    /// Encrypt given plaintext
    /// # Example
    /// ```
    /// use tinystorm::cipher::Cipher;
    ///
    /// let plaintext = "Hello, world!";
    /// let cipher = Cipher::from("25211840", "39").unwrap();
    ///
    /// let ciphertext = cipher.encrypt(plaintext).unwrap();
    /// println!("Ciphertext: {}", ciphertext); //xc-zu9ari !88
    /// ```
    pub fn encrypt(&self, plaintext: &str) -> Result<String, CipherError> {
        // Verifying size of our credentials
        self.credentials.verify_credentials_size(self.encoder.size)?;

        // Step 1: Encode
        let mut encoded = self.encoder.encode(plaintext);

        // Step 2: Adjust chunks
        let remainder = encoded.len() % CHUNK_SIZE;
        let adjusted = adjust_chunks(&mut encoded, remainder);

        self.encrypt_raw(adjusted);

        Ok(self.encoder.decode(adjusted))
    }

    /// Decrypt given ciphertext
    /// # Example
    /// ```
    /// use tinystorm::cipher::Cipher;
    /// let plaintext = "hello, world!";
    /// let cipher = Cipher::from("25211840", "39").unwrap();
    ///
    /// let ciphertext = cipher.encrypt(plaintext).unwrap();
    /// assert_eq!(ciphertext, "yd 0yc ehyrhjgdd".to_owned());
    ///
    /// let decrypted = cipher.decrypt(&ciphertext).unwrap();
    /// // .trim() needed since encryptor adjusts whitespaces to fill chunks
    /// assert_eq!(decrypted.trim(), plaintext);
    /// ```
    pub fn decrypt(&self, ciphertext: &str) -> Result<String, CipherError> {
        // Verifying size of our credentials
        self.credentials.verify_credentials_size(self.encoder.size)?;

        // As well, encode
        let mut encoded = self.encoder.encode(ciphertext);

        // We don't need to adjust the chunks here because if
        // ciphertext has malformed size, it is not our
        // problem =)
        self.decrypt_raw(&mut encoded);

        Ok(self.encoder.decode(&encoded))
    }

    /// Raw decrypt function. Not recommended to use
    pub fn decrypt_raw(&self, buffer: &mut [u8]) {
        // As well, expanding the key
        let key_capacity = buffer.len() / CHUNK_SIZE;
        let mut key = Vec::new();
        self.credentials.expand_key(&mut key, key_capacity, self.encoder.size);

        // Removing the key
        for (d, s) in buffer.iter_mut().zip(key.iter()) {
            *d = if *d < *s { *d + self.encoder.size } else { *d } - *s;
        }

        // Reverse chunk swap
        let chunks = buffer.chunks_exact_mut(CHUNK_SIZE);
        for chunk in chunks {
            reverse_chunk_swap(chunk, self.encoder.size);
        }
    }
}

pub(crate) fn adjust_chunks(buffer: &mut [u8], remainder: usize) -> &mut [u8] {
    let len = buffer.len();

    // Use it only if you sure that slice points to vector that can accept adjust
    unsafe {
        let vec_ptr = buffer.as_mut_ptr();
        let padding = 4 - remainder;

        for i in 0..padding {
            *vec_ptr.add(len + i) = 0;
        }

        std::slice::from_raw_parts_mut(vec_ptr, len + padding)
    }
}

fn swap_chunk(buffer: &mut [u8], range_mod: u8) {
    if buffer.len() < CHUNK_SIZE {
        return;
    }

    let [a, b, c, d] = [buffer[0], buffer[1], buffer[2], buffer[3]];

    let ab = (a + b) % range_mod;
    let cd = (c + d) % range_mod;

    buffer[1] = (ab + c) % range_mod;
    buffer[3] = (cd + b) % range_mod;
    buffer[0] = (ab + buffer[3]) % range_mod;
    buffer[2] = (cd + buffer[0]) % range_mod;
}

fn reverse_chunk_swap(buffer: &mut [u8], range_mod: u8) {
    if buffer.len() < CHUNK_SIZE {
        return;
    }

    let extract = |left: u8, right: u8| -> u8 {
        // If left is less than right, we assume finite field reset
        if left < right {
            left + range_mod - right
        } else {
            left - right
        }
    };

    let [a, b, c, d] = [buffer[0], buffer[1], buffer[2], buffer[3]];

    let c_unlinked = extract(c, a);
    let a_unlinked = extract(a, d);

    buffer[1] = extract(d, c_unlinked);
    buffer[0] = extract(a_unlinked, buffer[1]);
    buffer[2] = extract(b, a_unlinked);
    buffer[3] = extract(c_unlinked, buffer[2]);
}