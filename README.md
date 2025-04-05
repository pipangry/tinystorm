# Tinystorm
Tiny encryption algorithm designed for non-cryptography purposes.
Library implementation in Rust

## Getting started
Create cipher: encrypt and decrypt our message
```rust
fn main() {
    let plaintext = "hello, world!";
    let cipher = Cipher::from("25210840", "39").unwrap();

    let ciphertext = cipher.encrypt(plaintext).unwrap();
    println!("Ciphertext: {}", ciphertext);

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    // .trim() needed since encryptor adjusts whitespaces to fill chunks
    println!("Back to plaintext: {}", decrypted);
}
```
## About algorithm
Tinystorm is a toy encryption algorithm for educational purposes only. It is **designed as an algorithm that is easy to calculate manually.**

This algorithm assumes its own encoding, that is, the translation of characters into letters using a special table.
Calculations in this algorithm are mostly addition in finite field (range depends on your encoding)

For diffusion, Tinystorm uses step called 'swap chunk'. After swap chunk step it just applies key.
Your key reaches the desired size by generating it with an IV. The key consists of 4 numbers from zero to 99 (Since the key is separated by 2 digits), but each number can't be more than the limit of your encoding.
Therefore, variations of the key and IV can be up to 99^5 (9_509_900_499) depending on your encoding bounds.

## Inside of Algorithm Kitchen
So, I will tell you about how this algorithm works step by step.
First, we need to establish that this algorithm uses **chunks of 4 characters each**.
Since your key is split to 4 parts by each 2 digits, one-digit numbers should have 0 at the beginning (for example, 08)
#### Encryption steps:
1. Encoder encodes plaintext into array of `u8` depends on settings you selected. By default, encoder uses ENv1 table, which includes english alphabet (only lowercase), digits and some special characters. Characters that don't exist in encoding table will be removed. You can create your encoding table by using `Encoder::load(/**/)` or `Cipher::new(/**/).unwrap().load_encoder(/**/).unwrap()`.
2. Your key expanded from 4 numbers (That is, one chunk) to amount of your chunks * 4 using IV. Creating a new key works like this: an IV is added to each number of the previous key, then we apply 'swap key'.
3. You plaintext split by chunks (As well, 4 numbers each) and adjusted with zeros if it has remainder. On each chunk we apply 'swap chunk' logic
4. Your expanded key applies on swapped chunks using addition