use bip32::{ExtendedPrivateKey, ExtendedPublicKey, Mnemonic, Prefix, XPrv};
use rand_core::OsRng;
use bip32::secp256k1::ecdsa::{
    signature::{Signer, Verifier},
    Signature,
    SigningKey,
    VerifyingKey
};

fn hex_to_decimal_bytewise(hex_string: &str) -> Vec<u8> {
    let mut decimal_values = Vec::new();

    for hex_byte in hex_string.as_bytes().chunks(2) {
        let hex_str = if hex_byte.len() == 1 {
            // Handle odd-length hex strings by padding with a leading zero
            format!("0{}", char::from(hex_byte[0]))
        } else {
            format!("{}{}", char::from(hex_byte[0]), char::from(hex_byte[1]))
        };

        if let Ok(decimal_value) = u8::from_str_radix(&hex_str, 16) {
            decimal_values.push(decimal_value);
        } else {
            // Handle invalid hex characters
            panic!("Invalid hex character: {}", hex_str);
        }
    }

    decimal_values
}


// Derives a child private key based on a given index, between 0 - 2^(32)-1. 
fn derive_child_private_key(parent_xprv :ExtendedPrivateKey<SigningKey>, index: u32) -> ExtendedPrivateKey<SigningKey>{
    parent_xprv.derive_child(bip32::ChildNumber(index)).unwrap()
}
// Derives a child public key based on a given index, between 0 - 2^(32)-1. 
fn derive_child_public_key(parent_xpub :ExtendedPublicKey<VerifyingKey>, index: u32) -> ExtendedPublicKey<VerifyingKey>{
    parent_xpub.derive_child(bip32::ChildNumber(index)).unwrap()
}

// Question: we can also expose functions that derives keys from given string path too

// We would assume that the master Xprivate key will created in the keymanager and will be simply passed to these precompiles 


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

// testing the private and public key derivation functions 
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



// Test Vector 1 source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//let seed = String::from_utf8(hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()).unwrap();
let seed = hex_to_decimal_bytewise("000102030405060708090a0b0c0d0e0f");
let main_xpriv =  XPrv::new(&seed).unwrap();
assert_eq!(main_xpriv, XPrv::derive_from_path(&seed, &"m".parse().unwrap()).unwrap());

assert_eq!("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", main_xpriv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", main_xpriv.public_key().to_string(Prefix::XPUB).as_str());

let child_path = "m/0'";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


let child_path = "m/0'/1";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


let child_path = "m/0'/1/2'";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


let child_path = "m/0'/1/2'/2";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


let child_path = "m/0'/1/2'/2/1000000000";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


// Test Vector 2 source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 let seed = hex_to_decimal_bytewise("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
let main_xpriv =  XPrv::new(&seed).unwrap();
assert_eq!(main_xpriv, XPrv::derive_from_path(&seed, &"m".parse().unwrap()).unwrap());

assert_eq!("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U", main_xpriv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB", main_xpriv.public_key().to_string(Prefix::XPUB).as_str());

let child_path = "m/0";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


let child_path = "m/0/2147483647'";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


let child_path = "m/0/2147483647'/1";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


let child_path = "m/0/2147483647'/1/2147483646'";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL", child_xprv.public_key().to_string(Prefix::XPUB).as_str());


let child_path = "m/0/2147483647'/1/2147483646'/2";
let child_xprv = XPrv::derive_from_path(&seed, &child_path.parse()
.unwrap())
.unwrap();
assert_eq!("xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", child_xprv.to_string(Prefix::XPRV).as_str());
assert_eq!("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt", child_xprv.public_key().to_string(Prefix::XPUB).as_str());

}
