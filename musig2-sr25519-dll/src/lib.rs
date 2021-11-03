mod error;

// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::{JClass, JString};

// This is just a pointer. We'll be returning it from our function.
// We can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use jni::sys::{jint, jlong, jstring};

use self::error::Error;
use bip39::{Language, Mnemonic};
use mast::Mast;
use merlin::Transcript;
use musig2::{sign_double_prime, KeyAgg, Nv, State, StatePrime};
use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey};
use substrate_bip39::seed_from_entropy;

const PUBLICKEY_NORMAL_SIZE: usize = 32;
const ROUND1_MSG_SIZE: usize = Nv * PUBLICKEY_NORMAL_SIZE;
const STATE_PRIME_SIZE: usize = 64;

fn convert_string_to_jstring(env: JNIEnv, s: String) -> jstring {
    env.new_string(s)
        .expect("Couldn't create java string!")
        .into_inner()
}

/// Help to get the [`PublicKey`] from privkey
///
/// Returns: pubkey string
/// Possible errors are `Null KeyPair Pointer` and `Normal Error`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_get_1my_1pubkey(
    env: JNIEnv,
    _class: JClass,
    privkey: JString,
) -> jstring {
    match r_get_my_pubkey(env, privkey) {
        Ok(pri) => pri,
        Err(e) => convert_string_to_jstring(env, e.into()),
    }
}

pub fn r_get_my_pubkey(env: JNIEnv, privkey: JString) -> Result<jstring, Error> {
    let secret_bytes = c_char_to_r_bytes(env, privkey)?;

    let secret = SecretKey::from_bytes(&secret_bytes)?;
    let pubkey = secret.to_public();
    Ok(bytes_to_c_char(env, pubkey.to_bytes().to_vec()))
}

/// Pass in the public key to generate the aggregated public key
///
/// Returns: pubkey String.
/// Possible error is `Normal Error`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_get_1key_1agg(
    env: JNIEnv,
    _class: JClass,
    pubkeys: JString,
) -> jstring {
    match r_get_key_agg(env, pubkeys) {
        Ok(keypair) => keypair,
        Err(_) => convert_string_to_jstring(env, Error::NormalError.into()),
    }
}

pub fn r_get_key_agg(env: JNIEnv, pubkeys: JString) -> Result<jstring, Error> {
    let pubkeys_bytes = c_char_to_r_bytes(env, pubkeys)?;
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

    Ok(bytes_to_c_char(env, key_agg.X_tilde.to_bytes().to_vec()))
}

/// Generate the [`State`] of the first round
///
/// Returns: [`State`] Pointer.
/// If the calculation fails just a null pointer will be returned.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_get_1round1_1state(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    match r_get_round1_state() {
        Ok(s) => s,
        Err(_) => jlong::default(),
    }
}

pub fn r_get_round1_state() -> Result<jlong, Error> {
    let state = musig2::sign()?;
    Ok(Box::into_raw(Box::new(state)) as jlong)
}

/// encode [`State`] object.
///
/// Returns: state String.
/// Possible error is `Null Round1 State Pointer` or `Encode Fail`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_encode_1round1_1state(
    env: JNIEnv,
    _class: JClass,
    state: jlong,
) -> jstring {
    match r_encode_round1_state(env, state) {
        Ok(s) => s,
        Err(e) => convert_string_to_jstring(env, e.into()),
    }
}

pub fn r_encode_round1_state(env: JNIEnv, state: jlong) -> Result<jstring, Error> {
    let state = unsafe {
        // if state.is_null() {
        //     return Err(Error::NullRound1State);
        // }
        &mut *(state as *mut State)
    };
    match serde_json::to_string(state) {
        Ok(s) => Ok(convert_string_to_jstring(env, s)),
        Err(_) => Err(Error::EncodeFail),
    }
}

/// Use string to decode [`State`] object.
///
/// Returns: [`State`].
/// Failure will return a null pointer.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_decode_1round1_1state(
    env: JNIEnv,
    _class: JClass,
    round1_state: JString,
) -> jlong {
    match r_decode_round1_state(env, round1_state) {
        Ok(s) => s,
        Err(_) => jlong::default(),
    }
}

pub fn r_decode_round1_state(env: JNIEnv, round1_state: JString) -> Result<jlong, Error> {
    let round1_state: String = env
        .get_string(round1_state)
        .map_err(|_| Error::NullRound1State)?
        .into();
    let state = serde_json::from_str::<State>(&round1_state);
    match state {
        Ok(s) => Ok(Box::into_raw(Box::new(s)) as jlong),
        Err(_) => Err(Error::NullRound1State),
    }
}

/// Passed round1 [`State`] to generate msg which will broadcast
///
/// Returns: msg String.
/// Possible errors are `Normal Error` and `Null Round1 State Pointer`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_get_1round1_1msg(
    env: JNIEnv,
    _class: JClass,
    state: jlong,
) -> jstring {
    match r_get_round1_msg(env, state) {
        Ok(msg) => msg,
        Err(e) => convert_string_to_jstring(env, e.into()),
    }
}

pub fn r_get_round1_msg(env: JNIEnv, state: jlong) -> Result<jstring, Error> {
    let state = unsafe {
        // if state.is_null() {
        //     return Err(Error::NullRound1State);
        // }
        &mut *(state as *mut State)
    };

    let msg: Vec<[u8; 32]> = state
        .our_reveals()
        .iter()
        .map(|eph_key| eph_key.to_bytes())
        .collect();
    let msg_bytes = msg.concat();

    Ok(bytes_to_c_char(env, msg_bytes))
}

/// It takes a lot of preparation to switch to round2 state([`StatePrime`]).
/// You need the round1 [`State`], the message to sign for it,
/// your own public key, everyone's public key, and everyone else's
/// msgs from the round1.
///
/// Returns: [`StatePrime`] Pointer.
/// Failure will return a null pointer.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_get_1round2_1msg(
    env: JNIEnv,
    _class: JClass,
    round1_state: jlong,
    message: JString,
    privkey: JString,
    pubkeys: JString,
    received_round1_msg: JString,
) -> jstring {
    match r_get_round2_msg(
        env,
        round1_state,
        message,
        privkey,
        pubkeys,
        received_round1_msg,
    ) {
        Ok(state) => state,
        Err(e) => convert_string_to_jstring(env, e.into()),
    }
}

pub fn r_get_round2_msg(
    env: JNIEnv,
    round1_state: jlong,
    message: JString,
    privkey: JString,
    pubkeys: JString,
    received_round1_msg: JString,
) -> Result<jstring, Error> {
    let round1_state = unsafe {
        // if round1_state.is_null() {
        //     return Err(Error::NormalError);
        // }
        &mut *(round1_state as *mut State)
    };

    let (message, pubkeys, keypair, other_reveals) =
        round2_state_parse(env, message, privkey, pubkeys, received_round1_msg)?;

    let round2_state = round1_state.sign_prime(&message, &pubkeys, &keypair, other_reveals)?;
    Ok(bytes_to_c_char(env, round2_state.serialize().to_vec()))
}

#[allow(clippy::type_complexity)]
pub fn round2_state_parse(
    env: JNIEnv,
    message: JString,
    privkey: JString,
    pubkeys: JString,
    received_round1_msg: JString,
) -> Result<(Transcript, Vec<PublicKey>, Keypair, Vec<Vec<PublicKey>>), Error> {
    // construct message
    let message_bytes = c_char_to_r_bytes(env, message)?;
    let mut message = Transcript::new(b"SigningContext");
    message.append_message(b"", b"multi-sig");
    message.append_message(b"sign-bytes", &message_bytes);

    // construct pubkeys
    let pubkeys_bytes = c_char_to_r_bytes(env, pubkeys)?;
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
    let secret_bytes = c_char_to_r_bytes(env, privkey)?;
    let secret = SecretKey::from_bytes(&secret_bytes)?;
    let keypair = secret.to_keypair();

    // construct other_reveals
    let received_round1_msg_bytes = c_char_to_r_bytes(env, received_round1_msg)?;
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
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_get_1signature(
    env: JNIEnv,
    _class: JClass,
    receievd_round2_msg: JString,
) -> jstring {
    match r_get_signature(env, receievd_round2_msg) {
        Ok(sig) => sig,
        Err(e) => convert_string_to_jstring(env, e.into()),
    }
}

pub fn r_get_signature(env: JNIEnv, receievd_round2_msg: JString) -> Result<jstring, Error> {
    let r_receievd_round2_msg = c_char_to_r_bytes(env, receievd_round2_msg)?;

    let round2_msg_num = r_receievd_round2_msg.len() / STATE_PRIME_SIZE;
    let mut round2_msgs = Vec::new();
    for i in 0..round2_msg_num {
        let round2_msg = StatePrime::parse_slice(
            &r_receievd_round2_msg[i * STATE_PRIME_SIZE..i * STATE_PRIME_SIZE + STATE_PRIME_SIZE],
        )?;
        round2_msgs.push(round2_msg);
    }

    let s = sign_double_prime(&round2_msgs)?;

    Ok(bytes_to_c_char(env, s.to_bytes().to_vec()))
}

/// Help func
///
/// Convert rust's [`Vec<u8>`] type to a C string that can be called externally
pub fn bytes_to_c_char(env: JNIEnv, bytes: Vec<u8>) -> jstring {
    let hex_str = hex::encode(bytes);
    convert_string_to_jstring(env, hex_str)
}

/// Help func
///
/// Convert externally obtained C strings into [`Vec<u8>`] types used internally by rust
pub fn c_char_to_r_bytes(env: JNIEnv, input: JString) -> Result<Vec<u8>, Error> {
    let input: String = env
        .get_string(input)
        .map_err(|_| Error::NormalError)?
        .into();
    let r_bytes = hex::decode(&input)?;
    Ok(r_bytes)
}

/// Generate threshold signature addresses by passing in
/// all signer public keys and signature thresholds.
///
/// Returns: String. Return the public key of the threshold-signature address.
/// Possible error string returned is `Invalid Public Bytes`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Mast_generate_1threshold_1pubkey(
    env: JNIEnv,
    _class: JClass,
    pubkeys: JString,
    threshold: jint,
) -> jstring {
    match r_generate_tweak_pubkey(env, pubkeys, threshold as usize) {
        Ok(pubkey) => pubkey,
        Err(_) => convert_string_to_jstring(env, Error::InvalidPublicBytes.into()),
    }
}

pub fn r_generate_tweak_pubkey(
    env: JNIEnv,
    pubkeys: JString,
    threshold: usize,
) -> Result<jstring, Error> {
    let mast = r_get_my_mast(env, pubkeys, threshold)?;
    let tweak = mast.generate_tweak_pubkey()?;
    let tweak_hex = hex::encode(tweak);
    Ok(env
        .new_string(tweak_hex)
        .map_err(|_| Error::InvalidPublicBytes)?
        .into_inner())
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
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Mast_generate_1control_1block(
    env: JNIEnv,
    _class: JClass,
    pubkeys: JString,
    threshold: u8,
    agg_pubkey: JString,
) -> jstring {
    match r_generate_control_block(env, pubkeys, threshold as usize, agg_pubkey) {
        Ok(pubkey) => pubkey,
        Err(_) => convert_string_to_jstring(env, Error::InvalidPublicBytes.into()),
    }
}

pub fn r_generate_control_block(
    env: JNIEnv,
    pubkeys: JString,
    threshold: usize,
    agg_pubkey: JString,
) -> Result<jstring, Error> {
    let c_agg: String = env
        .get_string(agg_pubkey)
        .map_err(|_| Error::InvalidPublicBytes)?
        .into();
    let r_agg_bytes = hex::decode(&c_agg)?;
    let agg = PublicKey::from_bytes(&r_agg_bytes)?;

    let mast = r_get_my_mast(env, pubkeys, threshold)?;
    let control = mast.generate_merkle_proof(&agg)?;
    let control_hex = hex::encode(&control);
    Ok(convert_string_to_jstring(env, control_hex))
}

pub fn r_get_my_mast(env: JNIEnv, pubkeys: JString, threshold: usize) -> Result<Mast, Error> {
    // construct the public key of all people
    let c_pubkeys: String = env
        .get_string(pubkeys)
        .map_err(|_| Error::InvalidPublicBytes)?
        .into();
    let r_pubkeys_bytes = hex::decode(&c_pubkeys)?;
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
pub extern "system" fn Java_com_chainx_musig2_1sr25519_Musig2_get_1my_1privkey(
    env: JNIEnv,
    _class: JClass,
    phrase: JString,
) -> jstring {
    match r_get_my_privkey(env, phrase) {
        Ok(sec) => sec,
        Err(_) => convert_string_to_jstring(env, Error::InvalidPhrase.into()),
    }
}

fn r_get_my_privkey(env: JNIEnv, phrase: JString) -> Result<jstring, Error> {
    let phrase: String = env
        .get_string(phrase)
        .map_err(|_| Error::InvalidPhrase)?
        .into();
    let m = Mnemonic::from_phrase(&phrase, Language::English).map_err(|_| Error::InvalidPhrase)?;
    let seed = seed_from_entropy(m.entropy(), "").map_err(|_| Error::InvalidPhrase)?;
    let mini_key = MiniSecretKey::from_bytes(&seed[..32]).map_err(|_| Error::InvalidPhrase)?;
    let kp = mini_key.expand_to_keypair(ExpansionMode::Ed25519);
    let secret_str = hex::encode(&kp.secret.to_bytes());
    Ok(convert_string_to_jstring(env, secret_str))
}
