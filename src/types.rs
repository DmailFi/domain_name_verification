use std::env;

use bip39::{Mnemonic, Seed};
use ic_agent::{export::Principal, Identity, Signature};
use secp256k1::{ hashes::sha256, Message, Secp256k1, SecretKey};
use sha2::Sha256;
pub struct AppIdentity {
    secret: SecretKey
}

fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    // create a Sha256 object
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

impl AppIdentity {
    pub fn new() -> Self {
        let phrase = env::var("SEED_PHRASE").unwrap();
        let mnemonic = Mnemonic::from_phrase(&phrase, bip39::Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        let sk = SecretKey::from_slice(seed.as_bytes()).unwrap();

        Self { secret: sk }
    }
}

impl Identity for AppIdentity {
    fn sender(&self) -> Result<ic_agent::export::Principal, String> {
        Ok(Principal::self_authenticating(self.public_key().unwrap()))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        // Create a secp256k1 context
        let secp = Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &self.secret);
        Some(pk.serialize().to_vec())
    }

    fn sign(&self, content: &ic_agent::agent::EnvelopeContent) -> Result<ic_agent::Signature, String> {
        let secp = Secp256k1::new();
        let hash = sha256(&content.to_request_id().signable());
        let message = Message::from_hashed_data::<sha256::Hash>(&hash);
        // let message = Message::from_slice(&content.to_request_id().signable()).expect("32 bytes");

        let sig = Signature {
            public_key: self.public_key(),
            signature: Some(secp.sign_ecdsa(&message, &self.secret).serialize_compact().to_vec()),
            delegations: None
        };

        Ok(sig)
    }
}