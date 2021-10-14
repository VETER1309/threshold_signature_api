mod error;

use std::{
    ffi::{CStr, CString},
    ptr::null_mut,
};

use self::error::Error;
use libc::c_char;
use musig2::{
    get_party_index, sign_double_prime, KeyAgg, KeyPair, Nv, PrivateKey, PublicKey, State,
    StatePrime,
};

const PUBLICKEY_NORMAL_SIZE: usize = 65;
const PRIVATEKEY_NORMAL_SIZE: usize = 32;
const KEYPAIR_NORMAL_SIZE: usize = PUBLICKEY_NORMAL_SIZE + PRIVATEKEY_NORMAL_SIZE;
const ROUND1_MSG_SIZE: usize = Nv * PUBLICKEY_NORMAL_SIZE;

#[no_mangle]
pub extern "C" fn get_my_keypair(privkey: *const c_char) -> *mut KeyPair {
    match r_get_my_keypair(privkey) {
        Ok(keypair) => keypair,
        Err(_) => null_mut(),
    }
}

pub fn r_get_my_keypair(privkey: *const c_char) -> Result<*mut KeyPair, Error> {
    let secret_bytes = c_char_to_r_bytes(privkey)?;

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&secret_bytes[..]);
    let keypair = KeyPair::create_from_private_key(&bytes)?;

    Ok(Box::into_raw(Box::new(keypair)))
}

pub fn r_get_key_agg(
    pubkeys: *const c_char,
    my_pubkey: *const c_char,
) -> Result<*mut c_char, Error> {
    let my_pubkey_bytes = c_char_to_r_bytes(my_pubkey)?;
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(&my_pubkey_bytes);
    let my_pubkey = PublicKey::parse(&bytes)?;

    let pubkeys_bytes = c_char_to_r_bytes(pubkeys)?;
    let mut pubkeys = Vec::new();

    let pubkeys_num = pubkeys_bytes.len() / 65;

    for n in 0..pubkeys_num {
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(&pubkeys_bytes[n * 65..n * 65 + 65]);
        let pubkey = PublicKey::parse(&bytes)?;
        pubkeys.push(pubkey);
    }
    let party_index = get_party_index(&pubkeys, &my_pubkey)?;
    let key_agg = KeyAgg::key_aggregation_n(&pubkeys, party_index)?;
    let mut key_agg_bytes = [0u8; KEYPAIR_NORMAL_SIZE];
    key_agg_bytes[..65].copy_from_slice(&key_agg.X_tilde.serialize());
    key_agg_bytes[65..].copy_from_slice(&key_agg.a_i.serialize());
    Ok(r_bytes_to_c_char(key_agg_bytes.to_vec())?)
}

pub fn r_get_round1_state(keypair: *mut KeyPair) -> Result<*mut State, Error> {
    let keypair = unsafe {
        if keypair.is_null() {
            return Err(Error::NormalError);
        }
        &mut *keypair
    };

    let (_, state) = musig2::sign(keypair.clone())?;
    Ok(Box::into_raw(Box::new(state)))
}

pub fn r_get_round1_msg(state: *mut State) -> Result<*mut c_char, Error> {
    let state = unsafe {
        if state.is_null() {
            return Err(Error::NormalError);
        }
        &mut *state
    };

    let msg: Vec<[u8; 65]> = state
        .ephk_vec
        .iter()
        .map(|eph_key| eph_key.clone().keypair.public_key.serialize())
        .collect();
    let msg_bytes = msg.concat();

    Ok(r_bytes_to_c_char(msg_bytes)?)
}

pub fn r_get_round2_r(round2_state: *mut StatePrime) -> Result<*mut c_char, Error> {
    let round2_state = unsafe {
        if round2_state.is_null() {
            return Err(Error::NormalError);
        }
        &mut *round2_state
    };

    let r = round2_state.R.clone();
    Ok(r_bytes_to_c_char(r.serialize().to_vec())?)
}

pub fn r_get_round2_state(
    round1_state: *mut State,
    message: *const c_char,
    my_pubkey: *const c_char,
    pubkeys: *const c_char,
    receievd_round1_msg: *const c_char,
) -> Result<*mut StatePrime, Error> {
    let round1_state = unsafe {
        if round1_state.is_null() {
            return Err(Error::NormalError);
        }
        &mut *round1_state
    };
    let (message, pubkeys, receievd_round1_msg, party_index) = round2_state_parse(
        round1_state,
        message,
        my_pubkey,
        pubkeys,
        receievd_round1_msg,
    )?;

    let (round2_state, _) =
        round1_state.sign_prime(&message, &pubkeys, receievd_round1_msg, party_index)?;
    Ok(Box::into_raw(Box::new(round2_state)))
}

pub fn round2_state_parse(
    round1_state: &mut State,
    message: *const c_char,
    my_pubkey: *const c_char,
    pubkeys: *const c_char,
    receievd_round1_msg: *const c_char,
) -> Result<(Vec<u8>, Vec<PublicKey>, Vec<Vec<PublicKey>>, usize), Error> {
    let message_bytes = c_char_to_r_bytes(message)?;

    let my_pubkey_bytes = c_char_to_r_bytes(my_pubkey)?;
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(&my_pubkey_bytes);
    let my_pubkey = PublicKey::parse(&bytes)?;

    let pubkeys_bytes = c_char_to_r_bytes(pubkeys)?;
    let mut pubkeys = Vec::new();

    let pubkeys_num = pubkeys_bytes.len() / 65;

    for n in 0..pubkeys_num {
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(&pubkeys_bytes[n * 65..n * 65 + 65]);
        let pubkey = PublicKey::parse(&bytes)?;
        pubkeys.push(pubkey);
    }

    let received_round1_msg_bytes = c_char_to_r_bytes(receievd_round1_msg)?;
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

pub fn r_get_round2_msg(round2_state: *mut StatePrime) -> Result<*mut c_char, Error> {
    let round2_state = unsafe {
        if round2_state.is_null() {
            return Err(Error::NormalError);
        }
        &mut *round2_state
    };
    Ok(r_bytes_to_c_char(round2_state.s_i.serialize().to_vec())?)
}

pub fn r_get_signature(
    round2_state: *mut StatePrime,
    receievd_round2_msg: *const c_char,
    r: *const c_char,
) -> Result<*mut c_char, Error> {
    let round2_state = unsafe {
        if round2_state.is_null() {
            return Err(Error::NormalError);
        }
        &mut *round2_state
    };
    let r_receievd_round2_msg = c_char_to_r_bytes(receievd_round2_msg)?;
    let round2_msg_num = r_receievd_round2_msg.len() / PRIVATEKEY_NORMAL_SIZE;

    let mut round2_msgs = Vec::new();
    for i in 0..round2_msg_num {
        let mut round2_msg_byte = [0u8; 32];
        round2_msg_byte.copy_from_slice(&r_receievd_round2_msg[i * 32..i * 32 + 32]);
        let round2_msg = PrivateKey::parse(&round2_msg_byte)?;
        round2_msgs.push(round2_msg);
    }

    let s = sign_double_prime(round2_state.clone(), &round2_msgs)?;

    let r_bytes = c_char_to_r_bytes(r)?;
    let mut public_bytes = [0u8; PUBLICKEY_NORMAL_SIZE];
    public_bytes.copy_from_slice(&r_bytes);
    let r = PublicKey::parse(&public_bytes)?;

    let signature = [
        PrivateKey::parse_slice(&r.x_coor())?.serialize(),
        s.serialize(),
    ]
    .concat();
    Ok(r_bytes_to_c_char(signature)?)
}

/// Help func
///
/// Convert rust's [`Vec<u8>`] type to a C string that can be called externally
pub fn r_bytes_to_c_char(bytes: Vec<u8>) -> Result<*mut c_char, Error> {
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
    const PUBKEYA: &str = "f3fbf75d785b11d6fbd1d5dbd8defa10ddfbe77dde38a9810ec17352a21dbf0e";
    const PUBKEYB: &str = "e5512cb2c53c6e8719b46ed8a2c63b4537be790d0c5df10404401d51d99e3490";
    const PUBKEYC: &str = "ff4b91553015db3370eba90d05d8d90026ae1088c433e3cdf6f544a10b640b07";

    #[test]
    fn test_multiparty_signing_for_three_parties2() -> Result<(), Error> {
        let privkey_a = CString::new(PRIVATEA)?.into_raw();
        let privkey_b = CString::new(PRIVATEB)?.into_raw();
        let privkey_c = CString::new(PRIVATEC)?.into_raw();

        let keypair_a = get_my_keypair(privkey_a);
        let keypair_b = get_my_keypair(privkey_b);
        let keypair_c = get_my_keypair(privkey_c);

        let public_a = PublicKey::try_from(PUBKEYA)?;
        let public_b = PublicKey::try_from(PUBKEYB)?;
        let public_c = PublicKey::try_from(PUBKEYC)?;

        let pubkeys = [
            public_a.serialize().to_vec(),
            public_b.serialize().to_vec(),
            public_c.serialize().to_vec(),
        ]
        .concat();
        println!("pubkeya: {}", hex::encode(&public_a.serialize()));
        println!("pubkeyb: {}", hex::encode(&public_b.serialize()));
        println!("pubkeyc: {}", hex::encode(&public_c.serialize()));

        println!("pubkeys:{}", hex::encode(&pubkeys));
        let pubkeys = r_bytes_to_c_char(pubkeys)?;

        let public_a = r_bytes_to_c_char(public_a.serialize().to_vec())?;

        let public_b = r_bytes_to_c_char(public_b.serialize().to_vec())?;

        let public_c = r_bytes_to_c_char(public_c.serialize().to_vec())?;

        let round1_state_a = r_get_round1_state(keypair_a)?;
        let round1_state_b = r_get_round1_state(keypair_b)?;
        let round1_state_c = r_get_round1_state(keypair_c)?;

        let round1_msg_a = r_get_round1_msg(round1_state_a)?;
        let round1_msg_b = r_get_round1_msg(round1_state_b)?;
        let round1_msg_c = r_get_round1_msg(round1_state_c)?;

        let msg = PrivateKey::generate_random()?;
        let message = r_bytes_to_c_char(msg.serialize().to_vec())?;
        println!(
            "round1_msg1: {}",
            hex::encode(&c_char_to_r_bytes(round1_msg_b)?)
        );
        println!(
            "round1_msg2: {}",
            hex::encode(&c_char_to_r_bytes(round1_msg_c)?)
        );

        let round1_receieved_a = r_bytes_to_c_char(
            [
                c_char_to_r_bytes(round1_msg_b)?,
                c_char_to_r_bytes(round1_msg_c)?,
            ]
            .concat(),
        )?;
        let round1_receieved_b = r_bytes_to_c_char(
            [
                c_char_to_r_bytes(round1_msg_c)?,
                c_char_to_r_bytes(round1_msg_a)?,
            ]
            .concat(),
        )?;
        let round1_receieved_c = r_bytes_to_c_char(
            [
                c_char_to_r_bytes(round1_msg_a)?,
                c_char_to_r_bytes(round1_msg_b)?,
            ]
            .concat(),
        )?;

        let round2_state_a = r_get_round2_state(
            round1_state_a,
            message,
            public_a,
            pubkeys,
            round1_receieved_a,
        )?;
        let round2_state_b = r_get_round2_state(
            round1_state_b,
            message,
            public_b,
            pubkeys,
            round1_receieved_b,
        )?;
        let round2_state_c = r_get_round2_state(
            round1_state_c,
            message,
            public_c,
            pubkeys,
            round1_receieved_c,
        )?;

        let r_a = r_get_round2_r(round2_state_a)?;
        let r_b = r_get_round2_r(round2_state_b)?;
        let r_c = r_get_round2_r(round2_state_c)?;

        let round2_msg_a = r_get_round2_msg(round2_state_a)?;
        let round2_msg_b = r_get_round2_msg(round2_state_b)?;
        let round2_msg_c = r_get_round2_msg(round2_state_c)?;

        let round2_receieved_a = r_bytes_to_c_char(
            [
                c_char_to_r_bytes(round2_msg_b)?,
                c_char_to_r_bytes(round2_msg_c)?,
            ]
            .concat(),
        )?;
        let round2_receieved_b = r_bytes_to_c_char(
            [
                c_char_to_r_bytes(round2_msg_c)?,
                c_char_to_r_bytes(round2_msg_a)?,
            ]
            .concat(),
        )?;
        let round2_receieved_c = r_bytes_to_c_char(
            [
                c_char_to_r_bytes(round2_msg_a)?,
                c_char_to_r_bytes(round2_msg_b)?,
            ]
            .concat(),
        )?;

        let sig_a = r_get_signature(round2_state_a, round2_receieved_a, r_a)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&c_char_to_r_bytes(sig_a)?[..64]);

        let signature = Signature::try_from(sig_bytes)?;

        let r_sig = c_char_to_r_bytes(sig_a)?;
        println!("sig: {}", hex::encode(r_sig));

        let agg = r_get_key_agg(pubkeys, public_a)?;
        let mut agg_pubkey_bytes = [0u8; PUBLICKEY_NORMAL_SIZE];
        agg_pubkey_bytes.copy_from_slice(&c_char_to_r_bytes(agg)?[..65]);
        let agg_pubkey = PublicKey::parse(&agg_pubkey_bytes)?;

        println!("agg_pubkey: {}", hex::encode(&agg_pubkey.serialize()));

        assert!(verify(
            &signature,
            &Message::parse_slice(&msg.serialize()).unwrap(),
            &agg_pubkey,
        )?);

        Ok(())
    }
}
