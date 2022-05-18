//! A library to handle OpenSSH key and other common SSH key
//!
//! The main function of this library is to read, write different formats of SSH keys.
//! Also, it provide the ability to generate a key, sign and verify data.
//!
//! # Format Planning to Support
//! - Public Key
//!     - PEM
//!     - OpenSSH
//! - Private Key
//!     - PEM
//!     - OpenSSH v2
//!     - PuTTY
//!
//! # Supported Key Type
//! - DSA
//! - RSA
//! - EcDSA
//! - Ed25519
//!
//! ## Cargo Features
//! - `openssl-cipher`: [default] Using OpenSSL as symmetric cipher
//! - `rustcrypto-cipher`: Using RustCrypto as symmetric cipher
//!     - Choicing this does not remove the `openssl` dependency, since many places still require to use OpenSSL.
//! - `openssl-vendored`: Build with `openssl/vendored` feature
//!
//! # Example
//! ```rust
//! # #![allow(unused)]
//! # #[macro_use] extern crate hex_literal;
//! use osshkeys::{KeyPair, KeyType, Key as _, PublicParts as _, PrivateParts as _};
//! use osshkeys::keys::FingerprintHash;
//!
//! let keyfile = std::fs::read_to_string("assets/openssh_ed25519_enc").unwrap();
//! let keypair = KeyPair::from_keystr(&keyfile, Some("12345678")).unwrap();
//!
//! // Get the public key
//! let publickey = keypair.clone_public_key().unwrap();
//!
//! // Get the key type
//! assert_eq!(keypair.keytype(), KeyType::ED25519);
//!
//! // Get the fingerprint
//! assert_eq!(keypair.fingerprint(FingerprintHash::MD5).unwrap(), hex!("d29552b0c87d7ff1acb3c2229e783321"));
//!
//! // Sign some data
//! const SOME_DATA: &[u8] = b"8Kn9PPQV";
//! let sign = keypair.sign(SOME_DATA).unwrap();
//!
//! assert_eq!(sign.as_slice(), hex!("7206f04ef062ec35f8fb9f9e8a17ec023070ecf5f6e1021ea2af73137b1b832bba08766e5ad95fdca81af37b27898428f9a7dbeb044dd550afeb46efb94fe808").as_ref());
//! assert!(publickey.verify(SOME_DATA, &sign).unwrap());
//! ```

/// Containing the encrypt/decrypt algorithm
pub mod cipher;
/// Containing the error type of this crate
pub mod error;
/// Serialize/Deserialize key files
pub mod format;
/// Representing different types of public/private keys
pub mod keys;
/// Extension to read/write ssh data type representations defined in [RFC 4251](https://tools.ietf.org/html/rfc4251#section-5)
pub mod sshbuf;

pub use keys::Key;
pub use keys::KeyPair;
pub use keys::KeyType;
pub use keys::PrivateParts;
pub use keys::PublicKey;
pub use keys::PublicParts;
