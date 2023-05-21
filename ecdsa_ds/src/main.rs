use k256::{ecdsa::SigningKey, ecdsa::{VerifyingKey, Signature}, ecdsa::signature::Verifier, elliptic_curve::bigint::{U256, Encoding, Uint}, NonZeroScalar, FieldBytes, schnorr::signature::RandomizedSigner};
use rand::rngs::OsRng;

fn main() {
    // Init student ID used as private key
    let student_id: u32 = 6610009_u32;
    let secret_scalar: k256::elliptic_curve::NonZeroScalar<k256::Secp256k1> = NonZeroScalar::from_uint(Uint::from_u32(student_id)).unwrap();
    let secret_bytes: FieldBytes = FieldBytes::from(secret_scalar);
    
    // Step 1: Generate a private key from a specific integer and the corresponding public key.
    let private_key: SigningKey = SigningKey::from_bytes(&secret_bytes).unwrap();
    // let private_key: SigningKey = SigningKey::from_bytes(secret_bytes.as_slice().into()).unwrap();
    let public_key: VerifyingKey = VerifyingKey::from(&private_key);

    // Step 2: Sign the message.
    let hash_val: U256 = U256::from_be_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    let hash_bytes = hash_val.to_be_bytes();
    let signature: Signature = private_key.sign_with_rng(&mut OsRng, &hash_bytes);  // Sign with a random ephermeral key
    
    // Step 3: Print out Public key and signature
    println!("Public key: {:?}", public_key.to_encoded_point(false).to_string());
    println!("Signature (with a random ephermeral key):\n----------> {:?}", signature.to_string());
    
    // Step 4: Verify the signature using the public key.
    assert!(public_key.verify(&hash_bytes, &signature).is_ok());
    println!("(pass) Verify the signature using the public key");
    
}
