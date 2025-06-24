use tinystorm::cipher::Cipher;
use tinystorm::encoding::EncodingType;

fn main() {
    let plaintext = "Трюфель! Я не знаю что еще написать...";
    let mut cipher = Cipher::from("48070216", "35").unwrap();
    cipher.set_encoder(EncodingType::RUv5);

    let ciphertext = cipher.encrypt(plaintext).unwrap();
    println!("Ciphertext: {}", ciphertext);

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    // .trim() needed since encryptor adjusts whitespaces to fill chunks
    println!("Back to plaintext: {}", decrypted);
}