The Homomorphic Inventory Query System (HIQS) is a proof-of-concept project that demonstrates the use of homomorphic encryption to perform secure and privacy-preserving queries on an inventory database. Utilizing the TFHE (Fast Fully Homomorphic Encryption over the Torus) library, this project allows users to query encrypted data without the need to decrypt it, ensuring that sensitive information remains secure.

Features

Homomorphic Encryption: Leverages the TFHE library to perform computations on encrypted data.
Secure Queries: Allows querying of inventory data without exposing the underlying plaintext.
Privacy-Preserving: Ensures that both the query and the data remain confidential throughout the process.
Integer and Boolean Operations: Supports encrypted operations on integers and booleans using TFHE.
Installation
To get started with the Homomorphic Inventory Query System, follow these steps:

Clone the Repository:


git clone https://github.com/your-username/HomomorphicInventoryQuerySystem.git

cd HomomorphicInventoryQuerySystem

Install Dependencies:

Ensure you have Rust installed. Then, add the required dependencies to your Cargo.toml:


toml
[dependencies]
tfhe = "0.1"  # Replace with the actual version you're using
Build the Project:


cargo build
Usage
Generate Keys and Set Server Key:
The main function demonstrates how to generate keys and set the server key.

Define Inventory and Query:
You can define an example inventory and perform a query as shown in the main function.

Run the Project:

cargo run

Example Code

use tfhe::*;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8, FheInt32, FheInt8};
use tfhe::boolean::prelude::Ciphertext;

fn query(key: ServerKey, mut target: Ciphertext, inventory: &[(u8, u8)]) -> Ciphertext {
    // Create a zero ciphertext of the same type as target
    let mut zero_ciphertext = FheUint32::try_encrypt(target, &key);

    // Iterate through the inventory
    for (item_code, quantity) in inventory {
        // Convert the item code and quantity to ciphertexts using ClientKey
        let item_code_ciphertext = FheUint8::encrypt(*item_code, &key.clone().into());
        let quantity_ciphertext = FheUint32::encrypt(*quantity as u32, &key.clone().into());

        // Check if the target item code matches the current item code
        let is_match_ciphertext = key.equal(&item_code_ciphertext, &target);

        // If there's a match, add the quantity ciphertext to the target ciphertext
        target += if is_match_ciphertext.get_decrypt_with(key.clone().into()).unwrap() {
            &quantity_ciphertext
        } else {
            &zero_ciphertext
        };
    }

    // Return the updated target ciphertext
    target
}

fn main() {
    // Generate keys and set server key
    let config = ConfigBuilder::all_disabled().enable_default_integers().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    // Example inventory
    let inventory = [(1, 5), (2, 3), (3, 8)];

    // Example target ciphertext
    let target = FheUint8::try_encrypt(client_key.clone().into(), 2).to_ciphertext();

    // Perform the query
    let result = query(client_key.clone(), target, &inventory);

    // Decrypt and print the result
    let decrypted_result = result.get_decrypt_with(client_key.clone()).unwrap();
    println!("Result: {}", decrypted_result);
}
