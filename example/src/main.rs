use tinystorm::cipher::Cipher;
use tinystorm::encoding::EncodingType;

fn main() {
    let plaintext = "Hello, World!";
    let mut cipher = Cipher::from("18291340", "28").unwrap();
    cipher.set_encoder(EncodingType::ENv2);

    let ciphertext = cipher.encrypt(plaintext).unwrap();
    println!("Ciphertext: \"{ciphertext}\"");

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    // .trim() needed since encryptor adjusts whitespaces to fill chunks
    println!("Back to plaintext: {decrypted}");
}