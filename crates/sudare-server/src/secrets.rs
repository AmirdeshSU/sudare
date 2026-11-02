//! Randomness, hashing and XChaCha20-Poly1305 for values stored at rest.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use sha2::{Digest, Sha256};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS randomness");
    b
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn random_token() -> String {
    hex(&random_bytes::<32>())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// `nonce(24) || ciphertext`. `aad` binds the blob to where it belongs (user, slot).
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = random_bytes::<24>();
    let ct = XChaCha20Poly1305::new(&(*key).into())
        .encrypt(&nonce.into(), Payload { msg: plain, aad })
        .expect("in-memory encryption cannot fail");
    [nonce.as_slice(), &ct].concat()
}

pub fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 24 + 16 {
        return None;
    }
    let nonce: [u8; 24] = blob[..24].try_into().ok()?;
    XChaCha20Poly1305::new(&(*key).into())
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &blob[24..],
                aad,
            },
        )
        .ok()
}
