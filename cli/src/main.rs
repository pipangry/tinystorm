use tinystorm::cipher::Cipher;
use tinystorm::encoding::EncodingType;

fn main() {
    let plaintext = "Suspendisse tincidunt dolor leo, vel rutrum nunc varius in. Donec luctus ut ipsum nec vestibulum. Vivamus dapibus non lacus id sollicitudin. Nullam placerat tempor varius. Morbi placerat, tellus at rhoncus eleifend, tortor massa efficitur quam, quis aliquam urna sapien vel libero. Proin enim erat, aliquet a enim at, eleifend efficitur lacus. Interdum et malesuada fames ac ante ipsum primis in faucibus. Suspendisse ac ex imperdiet, bibendum tellus nec, dignissim orci. Suspendisse eget dolor a metus imperdiet faucibus at at libero. Duis dictum tristique est ac porta. Maecenas pharetra sed metus ac posuere. Maecenas vitae tempus ligula. Aenean posuere malesuada leo, in posuere risus. In eget lorem luctus, convallis sapien nec, placerat ipsum. Ut vitae purus vel libero posuere ornare auctor eget nisi. Praesent eleifend gravida arcu quis suscipit.";
    let mut cipher = Cipher::from("12350729", "47").unwrap();
    cipher.set_encoder(EncodingType::RUv5);

    let ciphertext = cipher.encrypt(plaintext).unwrap();
    println!("Ciphertext: {}", ciphertext);

    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    // .trim() needed since encryptor adjusts whitespaces to fill chunks
    println!("Back to plaintext: {}", decrypted);
}