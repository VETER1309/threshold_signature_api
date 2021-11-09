mod error;

use std::{
    ffi::{CStr, CString},
    ptr::null_mut,
};

use self::error::Error;
use bip39::{Language, Mnemonic};
use libc::c_char;
use mast::Mast;
use merlin::Transcript;
use musig2::{sign_double_prime, KeyAgg, Nv, State, StatePrime};
use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey};
use substrate_bip39::seed_from_entropy;

const PUBLICKEY_NORMAL_SIZE: usize = 32;
const ROUND1_MSG_SIZE: usize = Nv * PUBLICKEY_NORMAL_SIZE;
const STATE_PRIME_SIZE: usize = 64;

/// Help to get the [`PublicKey`] from privkey
///
/// Returns: pubkey string
/// Possible errors are `Null KeyPair Pointer` and `Normal Error`.
#[no_mangle]
pub extern "C" fn get_my_pubkey(privkey: *const c_char) -> *mut c_char {
    match r_get_my_pubkey(privkey) {
        Ok(pri) => pri,
        Err(e) => e.into(),
    }
}

pub fn r_get_my_pubkey(privkey: *const c_char) -> Result<*mut c_char, Error> {
    let secret_bytes = c_char_to_r_bytes(privkey)?;

    let secret = SecretKey::from_bytes(&secret_bytes)?;
    let pubkey = secret.to_public();
    bytes_to_c_char(pubkey.to_bytes().to_vec())
}

/// Pass in the public key to generate the aggregated public key
///
/// Returns: pubkey String.
/// Possible error is `Normal Error`.
#[no_mangle]
pub extern "C" fn get_key_agg(pubkeys: *const c_char) -> *mut c_char {
    match r_get_key_agg(pubkeys) {
        Ok(keypair) => keypair,
        Err(_) => Error::NormalError.into(),
    }
}

pub fn r_get_key_agg(pubkeys: *const c_char) -> Result<*mut c_char, Error> {
    let pubkeys_bytes = c_char_to_r_bytes(pubkeys)?;
    let mut pubkeys = Vec::new();

    if pubkeys_bytes.len() % PUBLICKEY_NORMAL_SIZE != 0 {
        return Err(Error::NormalError);
    }
    let pubkeys_num = pubkeys_bytes.len() / PUBLICKEY_NORMAL_SIZE;

    for n in 0..pubkeys_num {
        let mut bytes = [0u8; PUBLICKEY_NORMAL_SIZE];
        bytes.copy_from_slice(
            &pubkeys_bytes
                [n * PUBLICKEY_NORMAL_SIZE..n * PUBLICKEY_NORMAL_SIZE + PUBLICKEY_NORMAL_SIZE],
        );
        let pubkey = PublicKey::from_bytes(&bytes)?;
        pubkeys.push(pubkey);
    }
    let key_agg = KeyAgg::key_aggregation_n(&pubkeys)?;

    bytes_to_c_char(key_agg.X_tilde.to_bytes().to_vec())
}

/// Generate the [`State`] of the first round
///
/// Returns: [`State`] Pointer.
/// If the calculation fails just a null pointer will be returned.
#[no_mangle]
pub extern "C" fn get_round1_state() -> *mut State {
    match r_get_round1_state() {
        Ok(s) => s,
        Err(_) => null_mut(),
    }
}

pub fn r_get_round1_state() -> Result<*mut State, Error> {
    let state = musig2::sign()?;
    Ok(Box::into_raw(Box::new(state)))
}

/// encode [`State`] object.
///
/// Returns: state String.
/// Possible error is `Null Round1 State Pointer` or `Encode Fail`.
#[no_mangle]
pub extern "C" fn encode_round1_state(state: *mut State) -> *mut c_char {
    match r_encode_round1_state(state) {
        Ok(s) => s,
        Err(e) => e.into(),
    }
}

pub fn r_encode_round1_state(state: *mut State) -> Result<*mut c_char, Error> {
    let state = unsafe {
        if state.is_null() {
            return Err(Error::NullRound1State);
        }
        &mut *state
    };
    match serde_json::to_string(state) {
        Ok(s) => Ok(CString::new(s).map_err(|_| Error::EncodeFail)?.into_raw()),
        Err(_) => Err(Error::EncodeFail),
    }
}

/// Use string to decode [`State`] object.
///
/// Returns: [`State`].
/// Failure will return a null pointer.
#[no_mangle]
pub extern "C" fn decode_round1_state(round1_state: *const c_char) -> *mut State {
    match r_decode_round1_state(round1_state) {
        Ok(s) => s,
        Err(_) => null_mut(),
    }
}

pub fn r_decode_round1_state(round1_state: *const c_char) -> Result<*mut State, Error> {
    let round1_state = unsafe {
        if round1_state.is_null() {
            return Err(Error::NullRound1State);
        }

        CStr::from_ptr(round1_state)
    };
    let round1_state = round1_state.to_str()?;
    match serde_json::from_str(round1_state) {
        Ok(s) => Ok(Box::into_raw(Box::new(s))),
        Err(_) => Err(Error::NullRound1State),
    }
}

/// Passed round1 [`State`] to generate msg which will broadcast
///
/// Returns: msg String.
/// Possible errors are `Normal Error` and `Null Round1 State Pointer`.
#[no_mangle]
pub extern "C" fn get_round1_msg(state: *mut State) -> *mut c_char {
    match r_get_round1_msg(state) {
        Ok(msg) => msg,
        Err(e) => e.into(),
    }
}

pub fn r_get_round1_msg(state: *mut State) -> Result<*mut c_char, Error> {
    let state = unsafe {
        if state.is_null() {
            return Err(Error::NullRound1State);
        }
        &mut *state
    };

    let msg: Vec<[u8; 32]> = state
        .our_reveals()
        .iter()
        .map(|eph_key| eph_key.to_bytes())
        .collect();
    let msg_bytes = msg.concat();

    Ok(bytes_to_c_char(msg_bytes)?)
}

/// It takes a lot of preparation to switch to round2 state([`StatePrime`]).
/// You need the round1 [`State`], the message to sign for it,
/// your own public key, everyone's public key, and everyone else's
/// msgs from the round1.
///
/// Returns: [`StatePrime`] Pointer.
/// Failure will return a null pointer.
#[no_mangle]
pub extern "C" fn get_round2_msg(
    round1_state: *mut State,
    message: u32,
    privkey: *const c_char,
    pubkeys: *const c_char,
    received_round1_msg: *const c_char,
) -> *mut c_char {
    match r_get_round2_msg(round1_state, message, privkey, pubkeys, received_round1_msg) {
        Ok(state) => state,
        Err(_) => null_mut(),
    }
}

pub fn r_get_round2_msg(
    round1_state: *mut State,
    message: u32,
    privkey: *const c_char,
    pubkeys: *const c_char,
    received_round1_msg: *const c_char,
) -> Result<*mut c_char, Error> {
    let round1_state = unsafe {
        if round1_state.is_null() {
            return Err(Error::NormalError);
        }
        &mut *round1_state
    };

    let (message, pubkeys, keypair, other_reveals) =
        round2_state_parse(message, privkey, pubkeys, received_round1_msg)?;

    let round2_state = round1_state.sign_prime(&message, &pubkeys, &keypair, other_reveals)?;
    Ok(bytes_to_c_char(round2_state.serialize().to_vec())?)
}

pub fn round2_state_parse(
    message: u32,
    privkey: *const c_char,
    pubkeys: *const c_char,
    received_round1_msg: *const c_char,
) -> Result<(Transcript, Vec<PublicKey>, Keypair, Vec<Vec<PublicKey>>), Error> {
    // construct message
    let message_bytes = message.to_be_bytes();
    let mut message = Transcript::new(b"SigningContext");
    message.append_message(b"", b"multi-sig");
    message.append_message(b"sign-bytes", &message_bytes);

    // construct pubkeys
    let pubkeys_bytes = c_char_to_r_bytes(pubkeys)?;
    let mut pubkeys = Vec::new();

    let pubkeys_num = pubkeys_bytes.len() / PUBLICKEY_NORMAL_SIZE;

    for n in 0..pubkeys_num {
        let pubkey = PublicKey::from_bytes(
            &pubkeys_bytes
                [n * PUBLICKEY_NORMAL_SIZE..n * PUBLICKEY_NORMAL_SIZE + PUBLICKEY_NORMAL_SIZE],
        )?;
        pubkeys.push(pubkey);
    }

    // construct keypair
    let secret_bytes = c_char_to_r_bytes(privkey)?;
    let secret = SecretKey::from_bytes(&secret_bytes)?;
    let keypair = secret.to_keypair();

    // construct other_reveals
    let received_round1_msg_bytes = c_char_to_r_bytes(received_round1_msg)?;
    if received_round1_msg_bytes.len() % ROUND1_MSG_SIZE != 0 {
        return Err(Error::NormalError);
    }
    let round1_msg_num = received_round1_msg_bytes.len() / ROUND1_MSG_SIZE;

    let mut round1_msgs = Vec::new();
    for n in 0..round1_msg_num {
        let mut round1_msg_bytes = [0u8; ROUND1_MSG_SIZE];
        round1_msg_bytes.copy_from_slice(
            &received_round1_msg_bytes[n * ROUND1_MSG_SIZE..n * ROUND1_MSG_SIZE + ROUND1_MSG_SIZE],
        );
        let mut round1_msg = Vec::new();
        for i in 0..Nv {
            let pubkey = PublicKey::from_bytes(
                &round1_msg_bytes
                    [i * PUBLICKEY_NORMAL_SIZE..i * PUBLICKEY_NORMAL_SIZE + PUBLICKEY_NORMAL_SIZE],
            )?;
            round1_msg.push(pubkey);
        }
        round1_msgs.push(round1_msg);
    }

    Ok((message, pubkeys, keypair, round1_msgs))
}

/// To construct a signature requires the status of the round2
/// msg about the second round of all other signers, and its own R.
///
/// Returns: signature String.
/// Possible errors are `Normal Error` and `Null Round2 State Pointer`.
#[no_mangle]
pub extern "C" fn get_signature(receievd_round2_msg: *const c_char) -> *mut c_char {
    match r_get_signature(receievd_round2_msg) {
        Ok(sig) => sig,
        Err(e) => e.into(),
    }
}

pub fn r_get_signature(receievd_round2_msg: *const c_char) -> Result<*mut c_char, Error> {
    let r_receievd_round2_msg = c_char_to_r_bytes(receievd_round2_msg)?;

    let round2_msg_num = r_receievd_round2_msg.len() / STATE_PRIME_SIZE;
    let mut round2_msgs = Vec::new();
    for i in 0..round2_msg_num {
        let round2_msg = StatePrime::parse_slice(
            &r_receievd_round2_msg[i * STATE_PRIME_SIZE..i * STATE_PRIME_SIZE + STATE_PRIME_SIZE],
        )?;
        round2_msgs.push(round2_msg);
    }

    let s = sign_double_prime(&round2_msgs)?;

    bytes_to_c_char(s.to_bytes().to_vec())
}

/// Help func
///
/// Convert rust's [`Vec<u8>`] type to a C string that can be called externally
pub fn bytes_to_c_char(bytes: Vec<u8>) -> Result<*mut c_char, Error> {
    let hex_str = hex::encode(bytes);
    let c_str = CString::new(hex_str)?;
    Ok(c_str.into_raw())
}

/// Help func
///
/// Convert externally obtained C strings into [`Vec<u8>`] types used internally by rust
pub fn c_char_to_r_bytes(char: *const c_char) -> Result<Vec<u8>, Error> {
    let c_char = unsafe {
        if char.is_null() {
            return Err(Error::NormalError);
        }

        CStr::from_ptr(char)
    };
    let r_bytes = hex::decode(c_char.to_str()?)?;
    Ok(r_bytes)
}

/// Generate threshold signature addresses by passing in
/// all signer public keys and signature thresholds.
///
/// Returns: String. Return the public key of the threshold-signature address.
/// Possible error string returned is `Invalid Public Bytes`.
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

/// Generate a proof of the aggregated public key by
/// passing in the public key and signature threshold of
/// all signers and the aggregated public key of everyone
/// who performed the signature this time.
///
/// Returns: String.
/// Return signed proofs for transaction validation.
/// Possible error string returned is `Invalid Public Bytes`.
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
    use schnorrkel::Signature;

    use super::*;

    const PHRASE0: &str = "flame flock chunk trim modify raise rough client coin busy income smile";
    const PHRASE1: &str =
        "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics";
    const PHRASE2: &str =
        "awesome beef hill broccoli strike poem rebel unique turn circle cool system";
    const PUBLICA: &str = "005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d";
    const PUBLICB: &str = "90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547";
    const PUBLICC: &str = "66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415";
    const MESSAGE: u32 = 666666;

    fn convert_char_to_str(c: *mut c_char) -> String {
        let c_str = unsafe {
            assert!(!c.is_null());

            CStr::from_ptr(c)
        };
        c_str.to_str().unwrap().to_owned()
    }

    #[test]
    fn test_multiparty_signing() {
        let phrase_0 = CString::new(PHRASE0).unwrap().into_raw();
        let phrase_1 = CString::new(PHRASE1).unwrap().into_raw();
        let phrase_2 = CString::new(PHRASE2).unwrap().into_raw();
        let secret_key_0 = get_my_privkey(phrase_0);
        let secret_key_1 = get_my_privkey(phrase_1);
        let secret_key_2 = get_my_privkey(phrase_2);

        let pubkey_a = get_my_pubkey(secret_key_0);
        let pubkey_b = get_my_pubkey(secret_key_1);
        let pubkey_c = get_my_pubkey(secret_key_2);
        let pubkeys = bytes_to_c_char(
            [
                c_char_to_r_bytes(pubkey_a).unwrap(),
                c_char_to_r_bytes(pubkey_b).unwrap(),
                c_char_to_r_bytes(pubkey_c).unwrap(),
            ]
            .concat(),
        )
        .unwrap();

        let round1_state_a = get_round1_state();
        // round1_state_a serialization
        let round1_state_a = encode_round1_state(round1_state_a);
        // round1_state_a deserialization
        let round1_state_a = decode_round1_state(round1_state_a);
        let round1_state_b = get_round1_state();
        let round1_state_c = get_round1_state();

        let round1_msg_a = get_round1_msg(round1_state_a);
        let round1_msg_b = get_round1_msg(round1_state_b);
        let round1_msg_c = get_round1_msg(round1_state_c);

        let round1_received_a = bytes_to_c_char(
            [
                c_char_to_r_bytes(round1_msg_b).unwrap(),
                c_char_to_r_bytes(round1_msg_c).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let round1_received_b = bytes_to_c_char(
            [
                c_char_to_r_bytes(round1_msg_c).unwrap(),
                c_char_to_r_bytes(round1_msg_a).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let round1_received_c = bytes_to_c_char(
            [
                c_char_to_r_bytes(round1_msg_a).unwrap(),
                c_char_to_r_bytes(round1_msg_b).unwrap(),
            ]
            .concat(),
        )
        .unwrap();

        let round2_msg_a = get_round2_msg(
            round1_state_a,
            MESSAGE,
            secret_key_0,
            pubkeys,
            round1_received_a,
        );
        let round2_msg_b = get_round2_msg(
            round1_state_b,
            MESSAGE,
            secret_key_1,
            pubkeys,
            round1_received_b,
        );
        let round2_msg_c = get_round2_msg(
            round1_state_c,
            MESSAGE,
            secret_key_2,
            pubkeys,
            round1_received_c,
        );

        let round2_received = bytes_to_c_char(
            [
                c_char_to_r_bytes(round2_msg_a).unwrap(),
                c_char_to_r_bytes(round2_msg_b).unwrap(),
                c_char_to_r_bytes(round2_msg_c).unwrap(),
            ]
            .concat(),
        )
        .unwrap();

        let sig_char = get_signature(round2_received);

        let signature = Signature::from_bytes(&c_char_to_r_bytes(sig_char).unwrap()).unwrap();

        let r_sig = c_char_to_r_bytes(sig_char).unwrap();
        println!("agg_signature: {}", hex::encode(r_sig));

        let agg = get_key_agg(pubkeys);
        let agg_pubkey = PublicKey::from_bytes(&c_char_to_r_bytes(agg).unwrap()).unwrap();

        println!("agg_pubkey: {}", hex::encode(&agg_pubkey.to_bytes()));

        let mut message = Transcript::new(b"SigningContext");
        message.append_message(b"", b"multi-sig");
        let message_bytes = MESSAGE.to_be_bytes();
        message.append_message(b"sign-bytes", &message_bytes);
        assert!(agg_pubkey.verify(message, &signature).is_ok());
    }

    #[test]
    fn generate_mulsig_pubkey_should_work() {
        let pubkeys = PUBLICA.to_owned() + PUBLICB + PUBLICC;
        let pubkeys = CString::new(pubkeys.as_str()).unwrap().into_raw();

        let multi_pubkey = convert_char_to_str(generate_threshold_pubkey(pubkeys, 2));
        assert_eq!(
            "2623a598f40659352150c8fb5bdbd0baca6ae7d8e3cbefaad55b376e265d3c0e",
            multi_pubkey
        );
    }

    #[test]
    fn generate_control_block_should_work() {
        let pubkeys = PUBLICA.to_owned() + PUBLICB + PUBLICC;
        let pubkeys = CString::new(pubkeys.as_str()).unwrap().into_raw();
        let pubkeys_ab = PUBLICA.to_owned() + PUBLICB;
        let pubkeys_ab = CString::new(pubkeys_ab.as_str()).unwrap().into_raw();
        let ab_agg = get_key_agg(pubkeys_ab);
        let control = convert_char_to_str(generate_control_block(pubkeys, 2, ab_agg));
        assert_eq!("3870f07f65eb0f65e13cb53910966ea5fc7adad570d103a1e992b98e376c95420cddec2ff39d01b800a7b10550f553ffc02a749edb5fc43d9943818b3263c859", control);
    }
}
