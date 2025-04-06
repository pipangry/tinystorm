use crate::cipher::{adjust_chunks, Cipher, CHUNK_SIZE};
use crate::encoding::{Encoder, Encoding, EncodingType};
use crate::key::Credentials;

#[test]
fn encryption_test() {
    let plaintext = "hello, world!";
    let cipher = Cipher::from("25211840", "39").unwrap();

    let ciphertext = cipher.encrypt(plaintext).unwrap();
    assert_eq!(ciphertext, "yd 0yc ehyrhjgdd".to_owned());

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    // .trim() needed since encryptor adjusts whitespaces to fill chunks
    assert_eq!(decrypted.trim(), plaintext);
}

#[test]
fn encoding_test() {
    let encoder = Encoder::new(EncodingType::ENv1);
    let plaintext = "hello, world!";
    let encoded = encoder.encode(plaintext);
    let decoded = encoder.decode(&encoded);
    assert_eq!(decoded, plaintext);
}

#[test]
fn custom_encoding_test() {
    const MY_TABLE: Encoding = &[
        ('a', 1),
        ('b', 2),
        ('c', 3),
    ];
    let encoder = Encoder::load(MY_TABLE, false).unwrap();
    
    // d should be removed because it don't exist in encoding table
    let message = "abcd";
    let encoded = encoder.encode(message);
    
    assert_eq!(encoded, vec![1, 2, 3]);
}

#[test]
fn malformed_encoding_test() {
    // Table with repeated chars should be rejected
    const MY_TABLE: Encoding = &[
        ('a', 1),
        ('b', 2),
        ('b', 3),
    ];
    let encoder = Encoder::load(MY_TABLE, false);
    assert!(encoder.is_err());
}

#[test]
fn key_expansion_test() {
    let size = 4;
    
    let mut buffer = Vec::with_capacity(CHUNK_SIZE * size);
    let credentials = Credentials::new(&[1, 2, 3, 4], 27);
    
    credentials.expand_key(&mut buffer, size, 41);
    
    assert_eq!(buffer, vec![1, 2, 3, 4, 31, 17, 3, 30, 16, 2, 29, 15, 1, 28, 14, 0])
}

#[test]
fn chunks_adjust_test() {
    // Vec is critical here since adjust_chunks uses unsafe code for maximum performance
    let mut buffer = vec![1, 2, 3, 4, 5];
    let remainder = buffer.len() % CHUNK_SIZE;
    
    let adjusted = adjust_chunks(&mut buffer, remainder);
    assert_eq!(adjusted, vec![1, 2, 3, 4, 5, 0, 0, 0]);
}