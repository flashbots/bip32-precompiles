
use bip32::{ExtendedPrivateKey, ExtendedPublicKey, Mnemonic, Prefix, XPrv};
use rand_core::OsRng;
use bip32::secp256k1::ecdsa::{
    signature::{Signer, Verifier},
    Signature,
    SigningKey,
    VerifyingKey
};

fn derive_child_private_key(parent_xprv :ExtendedPrivateKey<SigningKey>, index: u32) -> ExtendedPrivateKey<SigningKey>{
    parent_xprv.derive_child(bip32::ChildNumber(index)).unwrap()
}

fn derive_child_public_key(parent_xpub :ExtendedPublicKey<VerifyingKey>, index: u32) -> ExtendedPublicKey<VerifyingKey>{
    parent_xpub.derive_child(bip32::ChildNumber(index)).unwrap()
}

fn main() {


// Generate random Mnemonic using the default language (English)
let mnemonic = Mnemonic::random(&mut OsRng, Default::default());

// Derive a BIP39 seed value using the given password
let seed = mnemonic.to_seed("password");

// Derive the root `XPrv` from the `seed` value
let root_xprv = XPrv::new(&seed).expect("failed to generate new xPriv key root");
assert_eq!(root_xprv, XPrv::derive_from_path(&seed, &"m".parse().expect("failed to parse the index")).expect("failed to derive private key"));

// Derive a child `XPrv` using the provided BIP32 derivation path
let child_path = "m/0/2147483647'/1/2147483646'";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.expect("failed to parse the child path"))
.expect("failed to derive from path");

// Get the `XPub` associated with `child_xprv`.
let child_xpub = child_xprv.public_key();

// Serialize `child_xprv` as a string with the `xprv` prefix.
let child_xprv_str = child_xprv.to_string(Prefix::XPRV);
assert!(child_xprv_str.starts_with("xprv"));

let new_child_priv = derive_child_private_key(child_xprv.clone(), 1);
let new_child_pub = new_child_priv.public_key();
let new_derived_child_pub = derive_child_public_key(child_xpub.clone(), 1);
let other_derived_child_pub = derive_child_public_key(child_xpub.clone(), 2);
assert!(new_child_pub.eq(&new_derived_child_pub));
assert!(new_child_pub.ne(&other_derived_child_pub));

// Serialize `child_xpub` as a string with the `xpub` prefix.
let child_xpub_str = child_xpub.to_string(Prefix::XPUB);
assert!(child_xpub_str.starts_with("xpub"));

// Get the ECDSA/secp256k1 signing and verification keys for the xprv and xpub
let signing_key = child_xprv.private_key();
let verification_key = child_xpub.public_key();

// Sign and verify an example message using the derived keys.
let example_msg = b"Hello, world!";
let signature: Signature = signing_key.sign(example_msg);
assert!(verification_key.verify(example_msg, &signature).is_ok());
}
