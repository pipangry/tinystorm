use crate::cipher::CHUNK_SIZE;
use crate::encoding::Encoder;
use crate::key::{swap_key, Credentials};

const MY_TABLE: &[(char, u8)] = &[
    ('a', 1),
    ('b', 2),
    ('c', 3),
];

#[test]
fn load_encoding() {
    // 4 Chunks
    let size = 4;
    
    // The size is how many chunks we have, so we can predict the required space
    let mut buffer = Vec::with_capacity(CHUNK_SIZE * size);
    let credentials = Credentials::new(&[1, 2, 3, 4], 27);
    // range_mod is modulus for finite field operations in key expansion,
    // set it to size of your encoding table (.len() + 1)
    credentials.expand_key(&mut buffer, size, 40);
    
    println!("{:?}", buffer);
}
