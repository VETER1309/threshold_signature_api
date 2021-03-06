use libc::c_char;
use mast::Mast;
use merlin::Transcript;
use std::{
    ffi::{CStr, CString},
    ptr::null_mut,
};

use schnorrkel::{
    musig::{
        aggregate_public_key_from_slice, collect_cosignatures, AggregatePublicKey, CosignStage,
        Cosignature, MuSig, Reveal, RevealStage,
    },
    signing_context, ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey,
};

mod error;

use bip39::{Language, Mnemonic};
use error::Error;
use substrate_bip39::seed_from_entropy;

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
    message: u32,
    privkey: *const c_char,
) -> *mut MuSig<Transcript, RevealStage<Keypair>> {
    match r_get_musig(message, privkey) {
        Ok(musig) => musig,
        Err(_) => null_mut(),
    }
}

pub fn r_get_musig(
    message: u32,
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
    let message = message.to_be_bytes();
    let t = signing_context(b"multi-sig").bytes(&message);
    let musig = MuSig::new(keypair, t).reveal_stage();
    Ok(Box::into_raw(Box::new(musig)))
}

#[no_mangle]
pub extern "C" fn encode_reveal_stage(
    musig: *mut MuSig<Transcript, RevealStage<Keypair>>,
) -> *mut c_char {
    match r_encode_reveal_stage(musig) {
        Ok(s) => s,
        Err(e) => e.into(),
    }
}

pub fn r_encode_reveal_stage(
    musig: *mut MuSig<Transcript, RevealStage<Keypair>>,
) -> Result<*mut c_char, Error> {
    let musig = unsafe {
        if musig.is_null() {
            return Err(Error::NullMusig);
        }
        &mut *musig
    };
    match serde_json::to_string(musig) {
        Ok(s) => Ok(CString::new(s).map_err(|_| Error::EncodeFail)?.into_raw()),
        Err(_) => Err(Error::EncodeFail),
    }
}

#[no_mangle]
pub extern "C" fn decode_reveal_stage(
    reveal_stage: *const c_char,
) -> *mut MuSig<Transcript, RevealStage<Keypair>> {
    match r_decode_reveal_stage(reveal_stage) {
        Ok(s) => s,
        Err(_) => null_mut(),
    }
}

pub fn r_decode_reveal_stage(
    reveal_stage: *const c_char,
) -> Result<*mut MuSig<Transcript, RevealStage<Keypair>>, Error> {
    let reveal_stage = unsafe {
        if reveal_stage.is_null() {
            return Err(Error::NullMusig);
        }

        CStr::from_ptr(reveal_stage)
    };
    let reveal_stage = reveal_stage.to_str()?;
    match serde_json::from_str(reveal_stage) {
        Ok(s) => Ok(Box::into_raw(Box::new(s))),
        Err(_) => Err(Error::NullMusig),
    }
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
pub extern "C" fn encode_cosign_stage(musig: *mut MuSig<Transcript, CosignStage>) -> *mut c_char {
    match r_encode_cosign_stage(musig) {
        Ok(s) => s,
        Err(e) => e.into(),
    }
}

pub fn r_encode_cosign_stage(
    musig: *mut MuSig<Transcript, CosignStage>,
) -> Result<*mut c_char, Error> {
    let musig = unsafe {
        if musig.is_null() {
            return Err(Error::NullMusig);
        }
        &mut *musig
    };
    match serde_json::to_string(musig) {
        Ok(s) => Ok(CString::new(s).map_err(|_| Error::EncodeFail)?.into_raw()),
        Err(_) => Err(Error::EncodeFail),
    }
}

#[no_mangle]
pub extern "C" fn decode_cosign_stage(
    reveal_stage: *const c_char,
) -> *mut MuSig<Transcript, CosignStage> {
    match r_decode_cosign_stage(reveal_stage) {
        Ok(s) => s,
        Err(_) => null_mut(),
    }
}

pub fn r_decode_cosign_stage(
    reveal_stage: *const c_char,
) -> Result<*mut MuSig<Transcript, CosignStage>, Error> {
    let reveal_stage = unsafe {
        if reveal_stage.is_null() {
            return Err(Error::NullMusig);
        }

        CStr::from_ptr(reveal_stage)
    };
    let reveal_stage = reveal_stage.to_str()?;
    match serde_json::from_str(reveal_stage) {
        Ok(s) => Ok(Box::into_raw(Box::new(s))),
        Err(_) => Err(Error::NullMusig),
    }
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
    message: u32,
    reveals: *const c_char,
    pubkeys: *const c_char,
    cosign: *const c_char,
) -> *mut c_char {
    match r_get_signature(message, reveals, pubkeys, cosign) {
        Ok(sig) => sig,
        Err(_) => Error::InvalidSignature.into(),
    }
}

pub fn r_get_signature(
    message: u32,
    reveals: *const c_char,
    pubkeys: *const c_char,
    cosign: *const c_char,
) -> Result<*mut c_char, Error> {
    let message = message.to_be_bytes();
    let t = signing_context(b"multi-sig").bytes(&message);
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

#[no_mangle]
pub extern "C" fn get_my_privkey(phrase: *const c_char) -> *mut c_char {
    match r_get_my_privkey(phrase) {
        Ok(sec) => sec,
        Err(_) => Error::InvalidPhrase.into(),
    }
}

fn r_get_my_privkey(phrase: *const c_char) -> Result<*mut c_char, Error> {
    let phrase = unsafe {
        if phrase.is_null() {
            return Err(Error::InvalidPhrase);
        }
        CStr::from_ptr(phrase)
    };
    let phrase = phrase.to_str()?;
    let m = Mnemonic::from_phrase(phrase, Language::English).map_err(|_| Error::InvalidPhrase)?;
    let seed = seed_from_entropy(m.entropy(), "").map_err(|_| Error::InvalidPhrase)?;
    let mini_key = MiniSecretKey::from_bytes(&seed[..32]).map_err(|_| Error::InvalidPhrase)?;
    let kp = mini_key.expand_to_keypair(ExpansionMode::Ed25519);
    let secret_str = CString::new(hex::encode(&kp.secret.to_bytes()))?;
    Ok(secret_str.into_raw())
}
#[cfg(test)]
mod tests {
    use super::*;
    use schnorrkel::Signature;

    const PHRASE0: &str = "flame flock chunk trim modify raise rough client coin busy income smile";
    const PHRASE1: &str =
        "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics";
    const PHRASE2: &str =
        "awesome beef hill broccoli strike poem rebel unique turn circle cool system";
    const MESSAGE: u32 = 666666;

    fn convert_char_to_str(c: *mut c_char) -> String {
        let c_str = unsafe {
            assert!(!c.is_null());

            CStr::from_ptr(c)
        };
        c_str.to_str().unwrap().to_owned()
    }

    #[test]
    fn multi_signature_should_work() {
        let phrase_0 = CString::new(PHRASE0).unwrap().into_raw();
        let phrase_1 = CString::new(PHRASE1).unwrap().into_raw();
        let phrase_2 = CString::new(PHRASE2).unwrap().into_raw();
        let secret_key_0 = get_my_privkey(phrase_0);
        let secret_key_1 = get_my_privkey(phrase_1);
        let secret_key_2 = get_my_privkey(phrase_2);
        let pubkey_0 = convert_char_to_str(get_my_pubkey(secret_key_0));
        let pubkey_1 = convert_char_to_str(get_my_pubkey(secret_key_1));
        let pubkey_2 = convert_char_to_str(get_my_pubkey(secret_key_2));

        let musig_0 = get_musig(MESSAGE, secret_key_0);
        // Reveal stage object serialization
        let musig_0 = encode_reveal_stage(musig_0);
        // Reveal stage object deserialization
        let musig_0 = decode_reveal_stage(musig_0);
        let musig_1 = get_musig(MESSAGE, secret_key_1);
        let musig_2 = get_musig(MESSAGE, secret_key_2);
        let pubkeys = pubkey_0 + &pubkey_1 + &pubkey_2;
        let pubkeys = CString::new(pubkeys.as_str()).unwrap().into_raw();
        let reveal_0 = convert_char_to_str(get_my_reveal(musig_0));
        let reveal_1 = convert_char_to_str(get_my_reveal(musig_1));
        let reveal_2 = convert_char_to_str(get_my_reveal(musig_2));
        let reveals = reveal_0 + reveal_1.as_str() + reveal_2.as_str();
        let reveals = CString::new(reveals.as_str()).unwrap().into_raw();
        let musig_0 = cosign_stage(musig_0, reveals, pubkeys);
        // Cosign stage object serialization
        let musig_0 = encode_cosign_stage(musig_0);
        // Cosign stage object deserialization
        let musig_0 = decode_cosign_stage(musig_0);
        let musig_1 = cosign_stage(musig_1, reveals, pubkeys);
        let musig_2 = cosign_stage(musig_2, reveals, pubkeys);
        let cosign_0 = convert_char_to_str(get_my_cosign(musig_0));
        let cosign_1 = convert_char_to_str(get_my_cosign(musig_1));
        let cosign_2 = convert_char_to_str(get_my_cosign(musig_2));
        let cosigns = cosign_0 + cosign_1.as_str() + cosign_2.as_str();
        let cosigns = CString::new(cosigns.as_str()).unwrap().into_raw();
        let signature = convert_char_to_str(get_signature(MESSAGE, reveals, pubkeys, cosigns));
        let signature = Signature::from_bytes(&hex::decode(signature).unwrap()).unwrap();
        let message = MESSAGE.to_be_bytes();
        let t = signing_context(b"multi-sig").bytes(&message);
        let pubkey = convert_char_to_str(get_agg_pubkey(pubkeys));
        let pubkey = PublicKey::from_bytes(&hex::decode(pubkey).unwrap()).unwrap();
        assert!(pubkey.verify(t.clone(), &signature).is_ok());
    }

    #[test]
    fn generate_mulsig_pubkey_should_work() {
        let phrase_0 = CString::new(PHRASE0).unwrap().into_raw();
        let phrase_1 = CString::new(PHRASE1).unwrap().into_raw();
        let phrase_2 = CString::new(PHRASE2).unwrap().into_raw();
        let secret_key_0 = get_my_privkey(phrase_0);
        let secret_key_1 = get_my_privkey(phrase_1);
        let secret_key_2 = get_my_privkey(phrase_2);
        let pubkey_a = convert_char_to_str(get_my_pubkey(secret_key_0));
        let pubkey_b = convert_char_to_str(get_my_pubkey(secret_key_1));
        let pubkey_c = convert_char_to_str(get_my_pubkey(secret_key_2));
        let pubkeys = pubkey_a.clone() + &pubkey_b + &pubkey_c;
        let pubkeys = CString::new(pubkeys.as_str()).unwrap().into_raw();

        let multi_pubkey = convert_char_to_str(generate_threshold_pubkey(pubkeys, 3));
        assert_eq!(
            "54f0f5b45dbf83059ccfb9fd9a28f6ed479018bd99bd6d8ae491fc804f657506",
            multi_pubkey
        );
    }

    #[test]
    fn generate_control_block_should_work() {
        let phrase_0 = CString::new(PHRASE0).unwrap().into_raw();
        let phrase_1 = CString::new(PHRASE1).unwrap().into_raw();
        let phrase_2 = CString::new(PHRASE2).unwrap().into_raw();
        let secret_key_0 = get_my_privkey(phrase_0);
        let secret_key_1 = get_my_privkey(phrase_1);
        let secret_key_2 = get_my_privkey(phrase_2);
        let pubkey_a = convert_char_to_str(get_my_pubkey(secret_key_0));
        let pubkey_b = convert_char_to_str(get_my_pubkey(secret_key_1));
        let pubkey_c = convert_char_to_str(get_my_pubkey(secret_key_2));
        let pubkeys = pubkey_a.clone() + &pubkey_b + &pubkey_c;
        let pubkeys = CString::new(pubkeys.as_str()).unwrap().into_raw();
        let pubkeys_ab = pubkey_a + &pubkey_b+&pubkey_c;
        let pubkeys_ab = CString::new(pubkeys_ab.as_str()).unwrap().into_raw();
        let ab_agg = get_agg_pubkey(pubkeys_ab);
        let control = convert_char_to_str(generate_control_block(pubkeys, 3, ab_agg));
        assert_eq!("1698edf8f66afe1f1fefc6f50800ae303af24407458a6d144e7da6b8954f166a", control);
    }
}
