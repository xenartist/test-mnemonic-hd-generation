use bip39::Mnemonic;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use std::str::FromStr;
use solana_sdk::{
    derivation_path::DerivationPath,
    signature::{keypair_from_seed_and_derivation_path, Signer},
};
use hex;

// Function to generate and verify keypair from mnemonic
fn verify_mnemonic(mnemonic_str: &str, passphrase: &str, expected_pubkey: &str) {
    // 1. Parse mnemonic
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    // 2. Generate seed with passphrase
    let salt = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];
    
    pbkdf2::<Hmac<Sha512>>(
        mnemonic.to_string().as_bytes(),
        salt.as_bytes(),
        2048,
        &mut seed
    );
    
    // Print the seed in hex format
    println!("Generated Seed (hex): {}", hex::encode(&seed));
    
    // Get master private key (directly from seed without derivation)
    let master_keypair = keypair_from_seed_and_derivation_path(&seed, None).unwrap();
    println!("Master Private Key (path: m) (hex): {}", 
        hex::encode(master_keypair.secret().as_bytes()));
    
    // 3. Derive child keypair from seed using path
    let path = "m/44'/501'/0'/0'";
    let derivation_path = DerivationPath::from_absolute_path_str(path).unwrap();
    let derived_keypair = keypair_from_seed_and_derivation_path(&seed, Some(derivation_path)).unwrap();
    
    // Print the derived private key
    println!("Derived Private Key (path: {}) (hex): {}", 
        path, hex::encode(derived_keypair.secret().as_bytes()));
    
    // 4. Get public key from derived keypair
    let pubkey = derived_keypair.pubkey();
    let pubkey_base58 = pubkey.to_string();
    
    // 5. Verify and print results
    println!("\nTesting mnemonic: {}", mnemonic_str);
    println!("Generated pubkey: {}", pubkey_base58);
    println!("Expected pubkey: {}", expected_pubkey);
    println!("Match: {}", pubkey_base58 == expected_pubkey);
}

fn main() {
    println!("Test Case 1 - Without passphrase:");
    verify_mnemonic(
        "grocery cash select sport hammer yellow install economy scene list pulp mail",
        "", // No passphrase
        "3BqdthK6iKXUUiuWAqgNZqvf564yodDXTsEwzkYe2ooM"
    );
    
    println!("\nTest Case 2 - With passphrase:");
    verify_mnemonic(
        "family convince crunch tail before baby someone slender bamboo flame armor motion",
        "1111", // Passphrase
        "3AitiX2a6cv5u78PoMkoRYCVJSKWH2mdGMEj89kAU1aH"
    );
}