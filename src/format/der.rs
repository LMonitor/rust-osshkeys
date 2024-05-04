use crate::error::*;
use crate::keys::{rsa::*, *};
use openssl::{
    pkey::{PKey, Public},
    rsa::Rsa,
};

pub fn to_der_pubkey(pubkey: &PublicKey) -> OsshResult<Vec<u8>> {
    let der = match &pubkey.key {
        PublicKeyType::RSA(key) => key.ossl_rsa().public_key_to_der()?,
        PublicKeyType::DSA(key) => key.ossl_pkey()?.public_key_to_der()?,
        PublicKeyType::ECDSA(key) => key.ossl_pkey()?.public_key_to_der()?,
        PublicKeyType::ED25519(key) => key.ossl_pkey()?.public_key_to_der()?,
    };

    Ok(der)
}

