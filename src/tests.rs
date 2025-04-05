use crate::cipher::{Cipher};
use crate::encoding::{Encoder, EncodingType};

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
fn test_encoding() {
    let encoder = Encoder::new(EncodingType::ENv1);
    let plaintext = "hello, world!";
    let encoded = encoder.encode(plaintext);
    let decoded = encoder.decode(&encoded);
    assert_eq!(decoded, plaintext);
}
