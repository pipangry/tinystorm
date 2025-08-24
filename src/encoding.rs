use crate::error::CipherError;

pub const DEFAULT_ENCODING: EncodingType = EncodingType::ENv1;
#[derive(Debug, Clone)]
pub enum EncodingType {
    RUv4,
    RUv5,
    ENv1,
    ENv2,
}

/// Encoding table represented as static array of (Char, encoded number). Can be created only with
/// [`encoding_table`] macro to perform compile-time checks
/// 
/// [`encoding_table`]: crate::encoding_table
#[derive(Debug, PartialEq)]
pub struct Encoding {
    inner: &'static [(char, u8)],
}

impl Encoding {
    #[doc(hidden)]
    /// Create new `Encoding` without compile-time check. Usage of this function is not recommended
    pub const fn new_unchecked(inner: &'static [(char, u8)]) -> Self {
        Self {
            inner,
        }
    }
}
#[macro_export]
/// Create new encoding with compile-time check
macro_rules! encoding_table {
    ($($enc:expr),*) => {{
        const INNER: &'static [(char, u8)] = &$($enc),*;
        
        const IS_VALID: bool = $crate::encoding::check_for_malformed_encoding(INNER);
        if !IS_VALID {
            panic!("Malformed encoding");
        }
        
        Encoding::new_unchecked(INNER)
    }};
}

/// Encoding table for english alphabet
const ENCODING_ENV1: Encoding = encoding_table!([
    (' ', 0),
    ('a', 1),
    ('b', 2),
    ('c', 3),
    ('d', 4),
    ('e', 5),
    ('f', 6),
    ('g', 7),
    ('h', 8),
    ('i', 9),
    ('j', 10),
    ('k', 11),
    ('l', 12),
    ('m', 13),
    ('n', 14),
    ('o', 15),
    ('p', 16),
    ('q', 17),
    ('r', 18),
    ('s', 19),
    ('t', 20),
    ('u', 21),
    ('v', 22),
    ('w', 23),
    ('x', 24),
    ('y', 25),
    ('z', 26),
    ('0', 27),
    ('1', 28),
    ('2', 29),
    ('3', 30),
    ('4', 31),
    ('5', 32),
    ('6', 33),
    ('7', 34),
    ('8', 35),
    ('9', 36),
    ('.', 37),
    (',', 38),
    ('!', 39),
    ('?', 40),
    ('-', 41)
]);

/// Extended encoding table for english alphabet
const ENCODING_ENV2: Encoding = encoding_table!([
    (' ', 0),
    ('a', 1),
    ('b', 2),
    ('c', 3),
    ('d', 4),
    ('e', 5),
    ('f', 6),
    ('g', 7),
    ('h', 8),
    ('i', 9),
    ('j', 10),
    ('k', 11),
    ('l', 12),
    ('m', 13),
    ('n', 14),
    ('o', 15),
    ('p', 16),
    ('q', 17),
    ('r', 18),
    ('s', 19),
    ('t', 20),
    ('u', 21),
    ('v', 22),
    ('w', 23),
    ('x', 24),
    ('y', 25),
    ('z', 26),
    ('A', 27),
    ('B', 28),
    ('C', 29),
    ('D', 30),
    ('E', 31),
    ('F', 32),
    ('G', 33),
    ('H', 34),
    ('I', 35),
    ('J', 36),
    ('K', 37),
    ('L', 38),
    ('M', 39),
    ('N', 40),
    ('O', 41),
    ('P', 42),
    ('Q', 43),
    ('R', 44),
    ('S', 45),
    ('T', 46),
    ('U', 47),
    ('V', 48),
    ('W', 49),
    ('X', 50),
    ('Y', 51),
    ('Z', 52),
    ('0', 53),
    ('1', 54),
    ('2', 55),
    ('3', 56),
    ('4', 57),
    ('5', 58),
    ('6', 59),
    ('7', 60),
    ('8', 61),
    ('9', 62),
    ('.', 63),
    (',', 64),
    ('!', 65),
    ('?', 66),
    ('-', 67),
    ('+', 68),
    ('@', 69),
]);

/// Encoding table for russian alphabet
const ENCODING_RUV5: Encoding = encoding_table!([
    (' ', 0),
    ('а', 1),
    ('б', 2),
    ('в', 3),
    ('г', 4),
    ('д', 5),
    ('е', 6),
    ('ё', 7),
    ('ж', 8),
    ('з', 9),
    ('и', 10),
    ('й', 11),
    ('к', 12),
    ('л', 13),
    ('м', 14),
    ('н', 15),
    ('о', 16),
    ('п', 17),
    ('р', 18),
    ('с', 19),
    ('т', 20),
    ('у', 21),
    ('ф', 22),
    ('х', 23),
    ('ц', 24),
    ('ч', 25),
    ('ш', 26),
    ('щ', 27),
    ('ъ', 28),
    ('ы', 29),
    ('ь', 30),
    ('э', 31),
    ('ю', 32),
    ('я', 33),
    ('0', 34),
    ('1', 35),
    ('2', 36),
    ('3', 37),
    ('4', 38),
    ('5', 39),
    ('6', 40),
    ('7', 41),
    ('8', 42),
    ('9', 43),
    ('.', 44),
    (',', 45),
    ('!', 46),
    ('?', 47),
    ('-', 48),
    ('+', 49),
    ('@', 50),
]);

/// Encoding table for russian alphabet, but without digits (OLD)
const ENCODING_RUV4: Encoding = encoding_table!([
    (' ', 0),
    ('а', 1),
    ('б', 2),
    ('в', 3),
    ('г', 4),
    ('д', 5),
    ('е', 6),
    ('ё', 7),
    ('ж', 8),
    ('з', 9),
    ('и', 10),
    ('й', 11),
    ('к', 12),
    ('л', 13),
    ('м', 14),
    ('н', 15),
    ('п', 16),
    ('т', 17),
    ('р', 18),
    ('о', 19),
    ('у', 20),
    ('с', 21),
    ('х', 22),
    ('ф', 23),
    ('ш', 24),
    ('щ', 25),
    ('ч', 26),
    ('ц', 27),
    ('ы', 28),
    ('э', 29),
    ('ю', 30),
    ('я', 31),
    ('ь', 32),
    ('ъ', 33),
    ('.', 34),
    (',', 35),
    ('!', 36),
    ('?', 37),
    ('+', 38),
    ('-', 39),
    ('@', 40),
]);

#[derive(Debug, PartialEq)]
pub struct Encoder {
    pub table: Encoding,
    support_uppercase: bool,
    pub size: u8,
}

impl Encoder {
    /// Create encoder from predefined encoding tables
    pub fn new(encoding: EncodingType) -> Self {
        match encoding {
            EncodingType::RUv4 => Self {
                table: ENCODING_RUV4,
                size: ENCODING_RUV4.inner.len() as u8,
                support_uppercase: false,
            },
            EncodingType::RUv5 => Self {
                table: ENCODING_RUV5,
                size: ENCODING_RUV5.inner.len() as u8,
                support_uppercase: false,
            },
            EncodingType::ENv1 => Self {
                table: ENCODING_ENV1,
                size: ENCODING_ENV1.inner.len() as u8,
                support_uppercase: false,
            },
            EncodingType::ENv2 => Self {
                table: ENCODING_ENV2,
                size: ENCODING_ENV2.inner.len() as u8,
                support_uppercase: true,
            },
        }
    }

    /// Load custom encoding table
    /// # Example
    /// ```
    /// use tinystorm::encoding::{Encoder, Encoding};
    /// use tinystorm::encoding_table;
    ///
    /// const MY_TABLE: Encoding = encoding_table!([
    ///     ('a', 1),
    ///     ('b', 2),
    ///     ('c', 3),
    /// ]);
    /// let encoder = Encoder::load(MY_TABLE, false).unwrap();
    /// ```
    pub fn load(encoding: Encoding, support_uppercase: bool) -> Result<Self, CipherError> {
        Ok(Self {
            size: encoding.inner.len() as u8,
            table: encoding,
            support_uppercase,
        })
    }

    /// Encode given str.
    /// If your encoder doesn't support uppercase,
    /// your chars will be converted to lowercase
    pub fn encode(&self, str: &str) -> Vec<u8> {
        str.chars()
            .filter_map(|c| {
                self.encode_char(if !self.support_uppercase {
                    c.to_lowercase().next().unwrap_or(c)
                } else {
                    c
                })
            })
            .collect()
    }

    /// Decode encoded bytes to string
    pub fn decode(&self, bytes: &[u8]) -> String {
        bytes.iter().filter_map(|&c| self.decode_char(c)).collect()
    }
}

// Private methods
impl Encoder {
    // Helper functions
    fn encode_char(&self, c: char) -> Option<u8> {
        self.table.inner.iter().find(|&&(ch, _)| ch == c).map(|&(_, n)| n)
    }

    fn decode_char(&self, n: u8) -> Option<char> {
        self.table.inner
            .iter()
            .find(|&&(_, num)| num == n)
            .map(|&(ch, _)| ch)
    }
}

/// Compile-time check for repeated chars in custom encoding table. Returns true if table is correct
pub const fn check_for_malformed_encoding(data: &[(char, u8)]) -> bool {
    let len = data.len();

    let mut i = 0;
    while i < len {
        // For each item check all other items
        let current_char = data[i].0;

        let mut next = i + 1;
        while next < len {
            // Check if it is the same
            if current_char == data[next].0 {
                return false;
            }
            next += 1;
        }
        i += 1;
    }

    true
}