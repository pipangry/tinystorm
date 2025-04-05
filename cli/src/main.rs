use tinystorm::cipher::Cipher;

fn main() {
    let plaintext = "Tinystorm encryption algorithm!";
    let cipher = Cipher::from("25210840", "39").unwrap();

    let ciphertext = cipher.encrypt(plaintext).unwrap();
    println!("Ciphertext: {}", ciphertext);

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    // .trim() needed since encryptor adjusts whitespaces to fill chunks
    println!("Back to plaintext: {}", decrypted);
}