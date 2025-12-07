//! Generate JWT for testing
//!
//! Usage: cargo run --example generate_jwt

use tana_auth::create_jwt_impl;

fn main() {
    // @sovereign private key
    let private_key = "ed25519_adaf348f3c5e2de4aa50ba802808f1017a22e650d47bc167ca5a2c641794d5ad";
    let username = "@sovereign";
    let network = "localhost:8501";
    let expiry_days = 90;

    match create_jwt_impl(private_key, username, network, expiry_days) {
        Ok(jwt) => {
            println!("{}", jwt);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
