use risc0_zkvm::guest::env;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

fn main() {
    let grandpa_proofs: Vec<(
        [u8; 32],
        Vec<u8>,
        Vec<u8>,
    )> = env::read();

    for (encoded_verifying_key, message, signature_bytes) in grandpa_proofs {
        let verifying_key = VerifyingKey::from_bytes(&encoded_verifying_key).unwrap();
        let signature: Signature = Signature::from_slice(&signature_bytes).unwrap();
        // Verify the signature, panicking if verification fails.
        // for _ in 0..iterations {
            verifying_key
                .verify(&message, &signature)
                .expect("Ed25519 signature verification failed");
    }


    // write public output to the journal
    env::commit(&42);
}
