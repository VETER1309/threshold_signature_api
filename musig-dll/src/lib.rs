use libc::c_char;
use mast::Mast;
use merlin::Transcript;
use std::{
    ffi::{CStr, CString},
    ptr::null_mut,
};

use schnorrkel::{
    musig::{
        aggregate_public_key_from_slice, collect_cosignatures, AggregatePublicKey,
        CosignStage, Cosignature, MuSig, Reveal, RevealStage,
    },
    signing_context, Keypair, PublicKey, SecretKey,
};

mod error;

use error::Error;

#[no_mangle]
pub extern "C" fn get_my_pubkey(privkey: *const c_char) -> *mut c_char {
    match r_get_my_pubkey(privkey) {
        Ok(pubkey) => pubkey,
        Err(_) => Error::InvalidSecretBytes.into(),
    }
}

pub fn r_get_my_pubkey(privkey: *const c_char) -> Result<*mut c_char, Error> {
    let c_priv = unsafe {
        if privkey.is_null() {
            return Err(Error::InvalidSecretBytes);
        }

        CStr::from_ptr(privkey)
    };

    let r_priv = c_priv.to_str()?;
    let secret_bytes = hex::decode(r_priv)?;

    let secret = SecretKey::from_bytes(&secret_bytes[..])?;
    let pubkey_hex = hex::encode(secret.to_public().to_bytes());
    let c_pubkey_str = CString::new(pubkey_hex)?;
    Ok(c_pubkey_str.into_raw())
}

#[no_mangle]
pub extern "C" fn get_musig(
    privkey: *const c_char,
) -> *mut MuSig<Transcript, RevealStage<Keypair>> {
    match r_get_musig(privkey) {
        Ok(musig) => musig,
        Err(_) => null_mut(),
    }
}

pub fn r_get_musig(
    privkey: *const c_char,
) -> Result<*mut MuSig<Transcript, RevealStage<Keypair>>, Error> {
    let c_priv = unsafe {
        if privkey.is_null() {
            return Err(Error::NullMusig);
        }

        CStr::from_ptr(privkey)
    };
    let r_priv = c_priv.to_str()?;
    let secret_bytes = hex::decode(r_priv)?;

    let secret = SecretKey::from_bytes(&secret_bytes[..])?;
    let keypair = Keypair::from(secret);
    let t = signing_context(b"multi-sig").bytes(b"We are legion!");
    let musig = MuSig::new(keypair, t).reveal_stage();
    Ok(Box::into_raw(Box::new(musig)))
}

#[no_mangle]
pub extern "C" fn get_my_reveal(
    musig: *mut MuSig<Transcript, RevealStage<Keypair>>,
) -> *mut c_char {
    let musig = unsafe {
        if musig.is_null() {
            return Error::NullMusig.into();
        }
        &mut *musig
    };

    let reveal = musig.our_reveal();
    let reveal_hex = hex::encode(reveal.0);
    let c_reveal_str = match CString::new(reveal_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Error::InvalidRevealBytes.into(),
    };
    c_reveal_str.into_raw()
}

#[no_mangle]
pub extern "C" fn cosign_stage(
    musig: *mut MuSig<Transcript, RevealStage<Keypair>>,
    reveals: *const c_char,
    pubkeys: *const c_char,
) -> *mut MuSig<Transcript, CosignStage> {
    match r_cosign_stage(musig, reveals, pubkeys) {
        Ok(musig) => musig,
        Err(_) => null_mut(),
    }
}

pub fn r_cosign_stage(
    musig: *mut MuSig<Transcript, RevealStage<Keypair>>,
    reveals: *const c_char,
    pubkeys: *const c_char,
) -> Result<*mut MuSig<Transcript, CosignStage>, Error> {
    let musig = unsafe {
        if musig.is_null() {
            return Err(Error::NullMusig);
        }
        &mut *musig
    };
    // construct the public key of all people
    let c_pubkeys = unsafe {
        if pubkeys.is_null() {
            return Err(Error::InvalidPublicBytes);
        }

        CStr::from_ptr(pubkeys)
    };

    let r_pubkeys_str = c_pubkeys.to_str()?;
    let r_pubkeys_bytes = hex::decode(r_pubkeys_str)?;
    // ensure that it is the correct public key length
    if r_pubkeys_bytes.len() % 32 != 0 {
        return Err(Error::InvalidPublicBytes);
    }
    let pubkeys_num = r_pubkeys_bytes.len() / 32;

    let c_reveals = unsafe {
        if reveals.is_null() {
            return Err(Error::InvalidRevealBytes);
        }

        CStr::from_ptr(reveals)
    };

    let r_reveals_str = c_reveals.to_str()?;
    let reveals_bytes = hex::decode(r_reveals_str)?;
    // ensure that it is the correct reveal length
    if reveals_bytes.len() % 96 != 0 {
        return Err(Error::InvalidRevealBytes);
    }
    let reveals_num = reveals_bytes.len() / 96;
    // make sure the number of public keys and the number of commits are the same
    if pubkeys_num != reveals_num {
        return Err(Error::IncorrectRevealNum);
    }

    for n in 0..pubkeys_num {
        let mut bytes = [0u8; 96];
        bytes.copy_from_slice(&reveals_bytes[n * 96..n * 96 + 96]);
        let reveal = Reveal(bytes);
        let publickey = PublicKey::from_bytes(&r_pubkeys_bytes[n * 32..n * 32 + 32])?;
        let _ = musig.add_their_reveal(publickey, reveal);
    }
    // get cosign
    let musig = musig.clone().cosign_stage();
    Ok(Box::into_raw(Box::new(musig)))
}

#[no_mangle]
pub extern "C" fn get_my_cosign(musig: *mut MuSig<Transcript, CosignStage>) -> *mut c_char {
    let musig = unsafe {
        if musig.is_null() {
            return Error::NullMusig.into();
        }
        &mut *musig
    };
    let cosign = musig.our_cosignature();
    let cosign_hex = hex::encode(cosign.0);
    let c_cosign_str = match CString::new(cosign_hex) {
        Ok(cosign) => cosign,
        Err(_) => return Error::InvalidCosignBytes.into(),
    };
    c_cosign_str.into_raw()
}

#[no_mangle]
pub extern "C" fn get_signature(
    reveals: *const c_char,
    pubkeys: *const c_char,
    cosign: *const c_char,
) -> *mut c_char {
    match r_get_signature(reveals, pubkeys, cosign) {
        Ok(sig) => sig,
        Err(_) => Error::InvalidSignature.into(),
    }
}

pub fn r_get_signature(
    reveals: *const c_char,
    pubkeys: *const c_char,
    cosign: *const c_char,
) -> Result<*mut c_char, Error> {
    let t = signing_context(b"multi-sig").bytes(b"We are legion!");
    let mut c = collect_cosignatures(t.clone());

    // construct the public key of all people
    let c_pubkeys = unsafe {
        if pubkeys.is_null() {
            return Err(Error::InvalidPublicBytes);
        }

        CStr::from_ptr(pubkeys)
    };
    let r_pubkeys_bytes = hex::decode(c_pubkeys.to_str()?)?;
    // ensure that it is the correct public key length
    if r_pubkeys_bytes.len() % 32 != 0 {
        return Err(Error::InvalidPublicBytes);
    }
    let pubkeys_num = r_pubkeys_bytes.len() / 32;

    let c_reveals = unsafe {
        if reveals.is_null() {
            return Err(Error::InvalidRevealBytes);
        }

        CStr::from_ptr(reveals)
    };

    let r_reveals_bytes = hex::decode(c_reveals.to_str()?)?;
    // ensure that it is the correct reveal length
    if r_reveals_bytes.len() % 96 != 0 {
        return Err(Error::InvalidRevealBytes);
    }
    let reveals_num = r_reveals_bytes.len() / 96;

    // construct the cosign of all people
    let c_cosign = unsafe {
        if cosign.is_null() {
            return Err(Error::InvalidCosignBytes);
        }

        CStr::from_ptr(cosign)
    };

    let r_cosign_bytes = hex::decode(c_cosign.to_str()?)?;
    // ensure that it is the correct cosign length
    if r_cosign_bytes.len() % 32 != 0 {
        return Err(Error::InvalidCosignBytes);
    }
    let cosign_num = r_cosign_bytes.len() / 32;

    // make sure the number of public keys and the number of commits are the same
    if pubkeys_num != reveals_num {
        return Err(Error::InvalidRevealBytes);
    }
    if pubkeys_num != cosign_num {
        return Err(Error::IncorrectRevealNum);
    }

    for n in 0..pubkeys_num {
        let mut reveal_bytes = [0u8; 96];
        reveal_bytes.copy_from_slice(&r_reveals_bytes[n * 96..n * 96 + 96]);
        let reveal = Reveal(reveal_bytes);
        let mut cosign_bytes = [0u8; 32];
        cosign_bytes.copy_from_slice(&r_cosign_bytes[n * 32..n * 32 + 32]);
        let cosign = Cosignature(cosign_bytes);
        let publickey = PublicKey::from_bytes(&r_pubkeys_bytes[n * 32..n * 32 + 32])?;

        let _ = c.add(publickey, reveal, cosign);
    }
    // get cosign
    let sig = c.signature();
    let sig_hex = hex::encode(sig.to_bytes());
    let c_sig_str = CString::new(sig_hex)?;
    Ok(c_sig_str.into_raw())
}

#[no_mangle]
pub extern "C" fn get_agg_pubkey(pubkeys: *const c_char) -> *mut c_char {
    match r_get_agg_pubkey(pubkeys) {
        Ok(pubkey) => pubkey,
        Err(_) => Error::InvalidPublicBytes.into(),
    }
}

pub fn r_get_agg_pubkey(pubkeys: *const c_char) -> Result<*mut c_char, Error> {
    // construct the public key of all people
    let c_pubkeys = unsafe {
        if pubkeys.is_null() {
            return Err(Error::InvalidPublicBytes);
        }

        CStr::from_ptr(pubkeys)
    };

    let r_pubkeys_bytes = hex::decode(c_pubkeys.to_str()?)?;
    // ensure that it is the correct public key length
    if r_pubkeys_bytes.len() % 32 != 0 {
        return Err(Error::InvalidPublicBytes);
    }
    let pubkeys_num = r_pubkeys_bytes.len() / 32;

    let mut pubkeys = Vec::<PublicKey>::new();
    for n in 0..pubkeys_num {
        let publickey = PublicKey::from_bytes(&r_pubkeys_bytes[n * 32..n * 32 + 32])?;
        pubkeys.push(publickey);
    }

    if let Some(agg) = aggregate_public_key_from_slice(&mut pubkeys) {
        let agg_pubkey = agg.public_key().to_bytes();
        let agg_hex = hex::encode(agg_pubkey);
        let c_agg_str = CString::new(agg_hex)?;
        Ok(c_agg_str.into_raw())
    } else {
        Err(Error::InvalidPublicBytes)
    }
}

#[no_mangle]
pub extern "C" fn generate_threshold_pubkey(pubkeys: *const c_char, threshold: u8) -> *mut c_char {
    match r_generate_tweak_pubkey(pubkeys, threshold as usize) {
        Ok(pubkey) => pubkey,
        Err(_) => Error::InvalidPublicBytes.into(),
    }
}

pub fn r_generate_tweak_pubkey(
    pubkeys: *const c_char,
    threshold: usize,
) -> Result<*mut c_char, Error> {
    let mast = r_get_my_mast(pubkeys, threshold)?;
    let tweak = mast.generate_tweak_pubkey()?;
    let tweak_hex = hex::encode(tweak);
    let c_tweak_str = CString::new(tweak_hex)?;
    Ok(c_tweak_str.into_raw())
}

#[no_mangle]
pub extern "C" fn generate_control_block(
    pubkeys: *const c_char,
    threshold: u8,
    agg_pubkey: *const c_char,
) -> *mut c_char {
    match r_generate_control_block(pubkeys, threshold as usize, agg_pubkey) {
        Ok(pubkey) => pubkey,
        Err(_) => Error::InvalidPublicBytes.into(),
    }
}

pub fn r_generate_control_block(
    pubkeys: *const c_char,
    threshold: usize,
    agg_pubkey: *const c_char,
) -> Result<*mut c_char, Error> {
    let c_agg = unsafe {
        if agg_pubkey.is_null() {
            return Err(Error::InvalidPublicBytes);
        }

        CStr::from_ptr(agg_pubkey)
    };

    let r_agg_bytes = hex::decode(c_agg.to_str()?)?;
    let agg = PublicKey::from_bytes(&r_agg_bytes)?;

    let mast = r_get_my_mast(pubkeys, threshold)?;
    let control = mast.generate_merkle_proof(&agg)?;
    let control_hex = hex::encode(&control);
    let c_control_str = CString::new(control_hex)?;
    Ok(c_control_str.into_raw())
}

pub fn r_get_my_mast(pubkeys: *const c_char, threshold: usize) -> Result<Mast, Error> {
    // construct the public key of all people
    let c_pubkeys = unsafe {
        if pubkeys.is_null() {
            return Err(Error::InvalidPublicBytes);
        }

        CStr::from_ptr(pubkeys)
    };

    let r_pubkeys_bytes = hex::decode(c_pubkeys.to_str()?)?;
    // ensure that it is the correct public key length
    if r_pubkeys_bytes.len() % 32 != 0 {
        return Err(Error::InvalidPublicBytes);
    }
    let pubkeys_num = r_pubkeys_bytes.len() / 32;

    let mut pubkeys = Vec::new();
    for n in 0..pubkeys_num {
        let publickey = PublicKey::from_bytes(&r_pubkeys_bytes[n * 32..n * 32 + 32])?;
        pubkeys.push(publickey);
    }

    Ok(Mast::new(pubkeys, threshold)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use schnorrkel::Signature;

    const PRIVATE0: &str = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2";
    const PRIVATE1: &str = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38";
    const PRIVATE2: &str = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59";
    const PUBLIC0: &str = "e283f9f07f5bae9a2ea1b4cfea313b3b5e29e0cac2dec126e788f0bf811ff82b";
    const PUBLIC1: &str = "40c01b70fe175c6db4f01d3ef5b4f96b5bc31f33d22b0a9b84f3ab75fc7e6c72";
    const PUBLIC2: &str = "dcb27a4ddd6f52216b294c8392d53b85099bbe9f7235914364334ee8f2ea707e";
    const PUBLICA: &str = "005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d";
    const PUBLICB: &str = "90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547";
    const PUBLICC: &str = "66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415";
    const PUBLICAB: &str = "7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861";

    fn convert_char_to_str(c: *mut c_char) -> String {
        let c_str = unsafe {
            assert!(!c.is_null());

            CStr::from_ptr(c)
        };
        c_str.to_str().unwrap().to_owned()
    }

    #[test]
    fn multi_signature_should_work() {
        let secret_key_0 = CString::new(PRIVATE0).unwrap().into_raw();
        let secret_key_1 = CString::new(PRIVATE1).unwrap().into_raw();
        let secret_key_2 = CString::new(PRIVATE2).unwrap().into_raw();
        let musig_0 = get_musig(secret_key_0);
        let musig_1 = get_musig(secret_key_1);
        let musig_2 = get_musig(secret_key_2);
        let pubkeys = PUBLIC0.to_owned() + PUBLIC1 + PUBLIC2;
        let pubkeys = CString::new(pubkeys.as_str()).unwrap().into_raw();
        let reveal_0 = convert_char_to_str(get_my_reveal(musig_0));
        let reveal_1 = convert_char_to_str(get_my_reveal(musig_1));
        let reveal_2 = convert_char_to_str(get_my_reveal(musig_2));
        let reveals = reveal_0 + reveal_1.as_str() + reveal_2.as_str();
        let reveals = CString::new(reveals.as_str()).unwrap().into_raw();
        let musig_0 = cosign_stage(musig_0, reveals, pubkeys);
        let musig_1 = cosign_stage(musig_1, reveals, pubkeys);
        let musig_2 = cosign_stage(musig_2, reveals, pubkeys);
        let cosign_0 = convert_char_to_str(get_my_cosign(musig_0));
        let cosign_1 = convert_char_to_str(get_my_cosign(musig_1));
        let cosign_2 = convert_char_to_str(get_my_cosign(musig_2));
        let cosigns = cosign_0 + cosign_1.as_str() + cosign_2.as_str();
        let cosigns = CString::new(cosigns.as_str()).unwrap().into_raw();
        let signature = convert_char_to_str(get_signature(reveals, pubkeys, cosigns));
        let signature = Signature::from_bytes(&hex::decode(signature).unwrap()).unwrap();

        let t = signing_context(b"multi-sig").bytes(b"We are legion!");
        let pubkey = convert_char_to_str(get_agg_pubkey(pubkeys));
        let pubkey = PublicKey::from_bytes(&hex::decode(pubkey).unwrap()).unwrap();
        assert!(pubkey.verify(t.clone(), &signature).is_ok());
    }

    #[test]
    fn generate_mulsig_pubkey_should_work() {
        let pubkeys = PUBLICA.to_owned() + PUBLICB + PUBLICC;
        let pubkeys = CString::new(pubkeys.as_str()).unwrap().into_raw();

        let multi_pubkey = convert_char_to_str(generate_threshold_pubkey(pubkeys, 2));
        assert_eq!(
            "d637ab113200c61d0188b6039de9738baa65d3e4f0d9f463a7aef8038c964021",
            multi_pubkey
        );
    }

    #[test]
    fn generate_control_block_should_work() {
        let pubkeys = PUBLICA.to_owned() + PUBLICB + PUBLICC;
        let pubkeys = CString::new(pubkeys.as_str()).unwrap().into_raw();

        let ab_agg = CString::new(PUBLICAB).unwrap().into_raw();
        let control = convert_char_to_str(generate_control_block(pubkeys, 2, ab_agg));
        assert_eq!("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c7680bac21362eecf9223bc477d6dfbbe02066a911eba752faedb26d881c466ea80fe17a23050f6f6db2f4218ce9f7c14edd21c5f24818157103c5a8524d7014c0dd", control);
    }
}
