mod error;

use std::{
    ffi::{CStr, CString},
    ptr::null_mut,
};

use self::error::Error;
use libc::c_char;
use musig2::{
    get_party_index, sign_double_prime, KeyAgg, KeyPair, Nv, PublicKey, State, StatePrime,
};

const PUBLICKEY_NORMAL_SIZE: usize = 65;
const PRIVATEKEY_NORMAL_SIZE: usize = 32;
const KEYPAIR_NORMAL_SIZE: usize = PUBLICKEY_NORMAL_SIZE + PRIVATEKEY_NORMAL_SIZE;
const ROUND1_MSG_SIZE: usize = Nv * PUBLICKEY_NORMAL_SIZE;
const STATE_PRIME_SIZE: usize = 97;

/// Pass in the 32-byte private key string to generate the [`KeyPair`]
///
/// Returns: [`KeyPair`] Pointer
/// If the keypair cannot be generated, a null pointer will be returned.
/// Note:
///   the [`KeyPair`] contains the personal [`PrivateKey`] and can only be used locally.
#[no_mangle]
pub extern "C" fn get_my_keypair(privkey: *const c_char) -> *mut KeyPair {
    match r_get_my_keypair(privkey) {
        Ok(keypair) => keypair,
        Err(_) => null_mut(),
    }
}

pub fn r_get_my_keypair(privkey: *const c_char) -> Result<*mut KeyPair, Error> {
    let secret_bytes = c_char_to_r_bytes(privkey)?;
    if secret_bytes.len() != 32 {
        return Err(Error::NormalError);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&secret_bytes[..]);
    let keypair = KeyPair::create_from_private_key(&bytes)?;

    Ok(Box::into_raw(Box::new(keypair)))
}

/// Help to get the [`PublicKey`] in the [`KeyPair`]
///
/// Returns: pubkey string
/// Possible errors are `Null KeyPair Pointer` and `Normal Error`.
#[no_mangle]
pub extern "C" fn get_my_pubkey(keypair: *mut KeyPair) -> *mut c_char {
    let keypair = unsafe {
        if keypair.is_null() {
            return Error::NullKeypair.into();
        }
        &mut *keypair
    };

    let pubkey = keypair.public_key.clone();
    match bytes_to_c_char(pubkey.serialize().to_vec()) {
        Ok(pubkey) => pubkey,
        Err(_) => Error::NormalError.into(),
    }
}

/// Pass in the public key to generate the aggregated public key
///
/// Returns: pubkey String
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

    if pubkeys_bytes.len() % 65 != 0 {
        return Err(Error::NormalError);
    }
    let pubkeys_num = pubkeys_bytes.len() / 65;

    for n in 0..pubkeys_num {
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(&pubkeys_bytes[n * 65..n * 65 + 65]);
        let pubkey = PublicKey::parse(&bytes)?;
        pubkeys.push(pubkey);
    }
    let key_agg = KeyAgg::key_aggregation_n(&pubkeys, 0)?;
    let mut key_agg_bytes = [0u8; KEYPAIR_NORMAL_SIZE];
    key_agg_bytes[..65].copy_from_slice(&key_agg.X_tilde.serialize());
    key_agg_bytes[65..].copy_from_slice(&key_agg.a_i.serialize());
    Ok(bytes_to_c_char(key_agg_bytes.to_vec())?)
}

/// Use [`KeyPair`] to calculate the [`State`] of the first round
///
/// Returns: [`State`] Pointer
/// If the calculation fails just a null pointer will be returned.
#[no_mangle]
pub extern "C" fn get_round1_state(keypair: *mut KeyPair) -> *mut State {
    match r_get_round1_state(keypair) {
        Ok(keypair) => keypair,
        Err(_) => null_mut(),
    }
}

pub fn r_get_round1_state(keypair: *mut KeyPair) -> Result<*mut State, Error> {
    let keypair = unsafe {
        if keypair.is_null() {
            return Err(Error::NullKeypair);
        }
        &mut *keypair
    };

    let (_, state) = musig2::sign(keypair.clone())?;
    Ok(Box::into_raw(Box::new(state)))
}

/// Passed round1 [`State`] to generate msg which will broadcast
///
/// Returns: msg String
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

    let msg: Vec<[u8; 65]> = state
        .ephk_vec
        .iter()
        .map(|eph_key| eph_key.clone().keypair.public_key.serialize())
        .collect();
    let msg_bytes = msg.concat();

    Ok(bytes_to_c_char(msg_bytes)?)
}

/// It takes a lot of preparation to switch to round2 state([`StatePrime`]).
/// You need the round1 [`State`], the message to sign for it,
/// your own public key, everyone's public key, and everyone else's
/// msgs from the round1.
///
/// Returns: [`StatePrime`] Pointer
/// Failure will return a null pointer.
#[no_mangle]
pub extern "C" fn get_round2_msg(
    round1_state: *mut State,
    message: *const c_char,
    my_pubkey: *const c_char,
    pubkeys: *const c_char,
    receievd_round1_msg: *const c_char,
) -> *mut c_char {
    match r_get_round2_msg(
        round1_state,
        message,
        my_pubkey,
        pubkeys,
        receievd_round1_msg,
    ) {
        Ok(state) => state,
        Err(_) => null_mut(),
    }
}

pub fn r_get_round2_msg(
    round1_state: *mut State,
    message: *const c_char,
    my_pubkey: *const c_char,
    pubkeys: *const c_char,
    receievd_round1_msg: *const c_char,
) -> Result<*mut c_char, Error> {
    let round1_state = unsafe {
        if round1_state.is_null() {
            return Err(Error::NormalError);
        }
        &mut *round1_state
    };
    let (message, pubkeys, receievd_round1_msg, party_index) =
        round2_state_parse(message, my_pubkey, pubkeys, receievd_round1_msg)?;

    let round2_state =
        round1_state.sign_prime(&message, &pubkeys, receievd_round1_msg, party_index)?;
    Ok(bytes_to_c_char(round2_state.serialize().to_vec())?)
}

pub fn round2_state_parse(
    message: *const c_char,
    my_pubkey: *const c_char,
    pubkeys: *const c_char,
    receievd_round1_msg: *const c_char,
) -> Result<(Vec<u8>, Vec<PublicKey>, Vec<Vec<PublicKey>>, usize), Error> {
    let message_bytes = c_char_to_r_bytes(message)?;

    let my_pubkey_bytes = c_char_to_r_bytes(my_pubkey)?;
    if my_pubkey_bytes.len() != 65 {
        return Err(Error::NormalError);
    }
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(&my_pubkey_bytes);
    let my_pubkey = PublicKey::parse(&bytes)?;

    let pubkeys_bytes = c_char_to_r_bytes(pubkeys)?;
    let mut pubkeys = Vec::new();
    if pubkeys_bytes.len() % 65 != 0 {
        return Err(Error::NormalError);
    }
    let pubkeys_num = pubkeys_bytes.len() / 65;

    for n in 0..pubkeys_num {
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(&pubkeys_bytes[n * 65..n * 65 + 65]);
        let pubkey = PublicKey::parse(&bytes)?;
        pubkeys.push(pubkey);
    }

    let received_round1_msg_bytes = c_char_to_r_bytes(receievd_round1_msg)?;
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
            let mut round1_msg_public_bytes = [0u8; PUBLICKEY_NORMAL_SIZE];
            round1_msg_public_bytes.copy_from_slice(
                &round1_msg_bytes
                    [i * PUBLICKEY_NORMAL_SIZE..i * PUBLICKEY_NORMAL_SIZE + PUBLICKEY_NORMAL_SIZE],
            );
            let pubkey = PublicKey::parse(&round1_msg_public_bytes)?;
            round1_msg.push(pubkey);
        }
        round1_msgs.push(round1_msg);
    }

    let party_index = get_party_index(&pubkeys, &my_pubkey)?;

    Ok((message_bytes, pubkeys, round1_msgs, party_index))
}

/// To construct a signature requires the status of the round2,
/// msg about the second round of all other signers, and its own R.
///
/// Returns: signature String
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
    if r_receievd_round2_msg.len() % STATE_PRIME_SIZE != 0 {
        return Err(Error::NormalError);
    }
    let round2_msg_num = r_receievd_round2_msg.len() / STATE_PRIME_SIZE;
    let mut round2_msgs = Vec::new();
    for i in 0..round2_msg_num {
        let mut round2_msg_byte = [0u8; 97];
        round2_msg_byte.copy_from_slice(&r_receievd_round2_msg[i * 97..i * 97 + 97]);
        let round2_msg = StatePrime::parse(&round2_msg_byte)?;
        round2_msgs.push(round2_msg);
    }

    let s = sign_double_prime(&round2_msgs)?;

    Ok(bytes_to_c_char(s.serialize().to_vec())?)
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

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use libsecp256k1::Message;
    use musig2::{verify, Signature};

    use super::*;

    const PRIVATEA: &str = "5495822c4f8efbe17b9bae42a85e8998baec458f3824440d1ce8d9357ad4a7b7";
    const PRIVATEB: &str = "cef4bbc9689812098c379bec0bb063a895916008344ca04cddbd21ccbcce3bcf";
    const PRIVATEC: &str = "c9045032eb6df7ebc51d862f9a6a8ffa90eb691dc1b70b4c7b8d1ed0fd8cc25f";
    const MESSAGE: &str = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38";

    fn convert_keypair_pointer(k: *mut KeyPair) -> KeyPair {
        let k = unsafe { &mut *k };
        k.clone()
    }

    #[test]
    fn test_multiparty_signing() {
        let privkey_a = CString::new(PRIVATEA).unwrap().into_raw();
        let privkey_b = CString::new(PRIVATEB).unwrap().into_raw();
        let privkey_c = CString::new(PRIVATEC).unwrap().into_raw();
        let msg = CString::new(MESSAGE).unwrap().into_raw();
        let keypair_a = get_my_keypair(privkey_a);
        let keypair_b = get_my_keypair(privkey_b);
        let keypair_c = get_my_keypair(privkey_c);
        let pubkey_a = convert_keypair_pointer(keypair_a).public_key.clone();
        let pubkey_b = convert_keypair_pointer(keypair_b).public_key.clone();
        let pubkey_c = convert_keypair_pointer(keypair_c).public_key.clone();
        let pubkeys = [
            pubkey_a.serialize().to_vec(),
            pubkey_b.serialize().to_vec(),
            pubkey_c.serialize().to_vec(),
        ]
        .concat();
        let pubkeys = bytes_to_c_char(pubkeys).unwrap();
        let pubkey_a = get_my_pubkey(keypair_a);
        let pubkey_b = get_my_pubkey(keypair_b);
        let pubkey_c = get_my_pubkey(keypair_c);

        let round1_state_a = get_round1_state(keypair_a);
        let round1_state_b = get_round1_state(keypair_b);
        let round1_state_c = get_round1_state(keypair_c);

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

        let round2_msg_a =
            get_round2_msg(round1_state_a, msg, pubkey_a, pubkeys, round1_received_a);
        let round2_msg_b =
            get_round2_msg(round1_state_b, msg, pubkey_b, pubkeys, round1_received_b);
        let round2_msg_c =
            get_round2_msg(round1_state_c, msg, pubkey_c, pubkeys, round1_received_c);

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
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&c_char_to_r_bytes(sig_char).unwrap()[..64]);
        let signature = Signature::try_from(sig_bytes).unwrap();

        let r_sig = c_char_to_r_bytes(sig_char).unwrap();
        println!("agg_signature: {}", hex::encode(r_sig));

        let agg = get_key_agg(pubkeys);
        let mut agg_pubkey_bytes = [0u8; PUBLICKEY_NORMAL_SIZE];
        agg_pubkey_bytes.copy_from_slice(&c_char_to_r_bytes(agg).unwrap()[..65]);
        let agg_pubkey = PublicKey::parse(&agg_pubkey_bytes).unwrap();

        println!("agg_pubkey: {}", hex::encode(&agg_pubkey.serialize()));

        verify(
            &signature,
            &Message::parse_slice(&hex::decode(&MESSAGE).unwrap()).unwrap(),
            &agg_pubkey,
        )
        .unwrap();
    }
}
