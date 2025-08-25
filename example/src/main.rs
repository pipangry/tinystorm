use tinystorm::cipher::Cipher;
use tinystorm::encoding::EncodingType;

fn main() {
    let plaintext = "I like kitties";
    let mut cipher = Cipher::new("30504259", "23").unwrap();
    cipher.set_encoder(EncodingType::ENv2);

    let ciphertext = cipher.encrypt(plaintext).unwrap();
    println!("Ciphertext: \"{ciphertext}\"");

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    println!("Back to plaintext: \"{decrypted}\"");
}