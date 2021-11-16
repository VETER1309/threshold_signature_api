mod error;

use rand_core::{OsRng, RngCore};
use std::str::FromStr;

use bip0039::Mnemonic;
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
use light_bitcoin::chain::{
    hash_rev, Bytes, OutPoint, Transaction, TransactionInput, TransactionOutput, H256,
};
use light_bitcoin::keys::{sign_with_aux, Address};
use light_bitcoin::script::{
    Builder, Opcode, ScriptExecutionData, SignatureVersion, TransactionInputSigner,
};
use light_bitcoin::serialization::{serialize_with_flags, SERIALIZE_TRANSACTION_WITNESS};

use self::error::Error;
use light_bitcoin::mast::Mast;
use musig2::{sign_double_prime, KeyAgg, KeyPair, Nv, PrivateKey, PublicKey, State, StatePrime};

const PUBLICKEY_NORMAL_SIZE: usize = 65;
const ROUND1_MSG_SIZE: usize = Nv * PUBLICKEY_NORMAL_SIZE;
const STATE_PRIME_SIZE: usize = 97;

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
pub extern "system" fn Java_com_chainx_musig2_Musig2_get_1my_1pubkey(
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
    if secret_bytes.len() != 32 {
        return Err(Error::NormalError);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&secret_bytes[..]);
    let pubkey = PublicKey::create_from_private_key(&PrivateKey::parse(&bytes)?);
    Ok(bytes_to_c_char(env, pubkey.serialize().to_vec()))
}

/// Pass in the public key to generate the aggregated public key
///
/// Returns: pubkey String.
/// Possible error is `Normal Error`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Musig2_get_1key_1agg(
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
    let key_agg = KeyAgg::key_aggregation_n(&pubkeys)?;
    let mut key_agg_bytes = [0u8; PUBLICKEY_NORMAL_SIZE];
    key_agg_bytes[..65].copy_from_slice(&key_agg.X_tilde.serialize());
    Ok(bytes_to_c_char(env, key_agg_bytes.to_vec()))
}

/// Generate the [`State`] of the first round
///
/// Returns: [`State`] Pointer.
/// If the calculation fails just a null pointer will be returned.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Musig2_get_1round1_1state(
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
pub extern "system" fn Java_com_chainx_musig2_Musig2_encode_1round1_1state(
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
pub extern "system" fn Java_com_chainx_musig2_Musig2_decode_1round1_1state(
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
pub extern "system" fn Java_com_chainx_musig2_Musig2_get_1round1_1msg(
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

    let msg: Vec<[u8; 65]> = state
        .our_reveals()
        .iter()
        .map(|eph_key| eph_key.serialize())
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
pub extern "system" fn Java_com_chainx_musig2_Musig2_get_1round2_1msg(
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
    let (message, pubkeys, received_round1_msg, keypair) =
        round2_state_parse(env, message, privkey, pubkeys, received_round1_msg)?;

    let round2_state =
        round1_state.sign_prime(&message, &pubkeys, &keypair, received_round1_msg)?;
    Ok(bytes_to_c_char(env, round2_state.serialize().to_vec()))
}

#[allow(clippy::type_complexity)]
pub fn round2_state_parse(
    env: JNIEnv,
    message: JString,
    privkey: JString,
    pubkeys: JString,
    received_round1_msg: JString,
) -> Result<(Vec<u8>, Vec<PublicKey>, Vec<Vec<PublicKey>>, KeyPair), Error> {
    let message_bytes = c_char_to_r_bytes(env, message)?;

    let secret_bytes = c_char_to_r_bytes(env, privkey)?;
    if secret_bytes.len() != 32 {
        return Err(Error::NormalError);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&secret_bytes[..]);
    let keypair = KeyPair::create_from_private_key(&bytes)?;

    let pubkeys_bytes = c_char_to_r_bytes(env, pubkeys)?;
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

    Ok((message_bytes, pubkeys, round1_msgs, keypair))
}

/// To construct a signature requires the status of the round2
/// msg about the second round of all other signers, and its own R.
///
/// Returns: signature String.
/// Possible errors are `Normal Error` and `Null Round2 State Pointer`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Musig2_get_1signature(
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

    Ok(bytes_to_c_char(env, s.serialize().to_vec()))
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
pub extern "system" fn Java_com_chainx_musig2_Mast_generate_1threshold_1pubkey(
    env: JNIEnv,
    _class: JClass,
    pubkeys: JString,
    threshold: jint,
    network: JString,
) -> jstring {
    match r_generate_tweak_pubkey(env, pubkeys, threshold as usize, network) {
        Ok(pubkey) => pubkey,
        Err(_) => convert_string_to_jstring(env, Error::InvalidPublicBytes.into()),
    }
}

pub fn r_generate_tweak_pubkey(
    env: JNIEnv,
    pubkeys: JString,
    threshold: usize,
    network: JString,
) -> Result<jstring, Error> {
    let mast = r_get_my_mast(env, pubkeys, threshold)?;
    let network: String = env
        .get_string(network)
        .map_err(|_| Error::NormalError)?
        .into();
    let tweak = mast.generate_address(&network)?;
    Ok(env
        .new_string(tweak)
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
pub extern "system" fn Java_com_chainx_musig2_Mast_generate_1control_1block(
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
    let mut keys = [0u8; PUBLICKEY_NORMAL_SIZE];
    keys.copy_from_slice(&r_agg_bytes[0..PUBLICKEY_NORMAL_SIZE]);
    let agg = PublicKey::parse(&keys)?;

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
    if r_pubkeys_bytes.len() % PUBLICKEY_NORMAL_SIZE != 0 {
        return Err(Error::InvalidPublicBytes);
    }
    let pubkeys_num = r_pubkeys_bytes.len() / PUBLICKEY_NORMAL_SIZE;

    let mut pubkeys = Vec::new();
    for n in 0..pubkeys_num {
        let mut keys = [0u8; PUBLICKEY_NORMAL_SIZE];
        keys.copy_from_slice(
            &r_pubkeys_bytes
                [n * PUBLICKEY_NORMAL_SIZE..n * PUBLICKEY_NORMAL_SIZE + PUBLICKEY_NORMAL_SIZE],
        );
        let publickey = PublicKey::parse(&keys)?;
        pubkeys.push(publickey);
    }

    Ok(Mast::new(pubkeys, threshold)?)
}

/// Add the first input[txid + outpoint's index] to initialize basic transactions
///
/// Returns: String.
/// Return the base tx hex string.
/// Possible error string returned is `Invalid Transaction`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_get_1base_1tx(
    env: JNIEnv,
    _class: JClass,
    txid: JString,
    index: jlong,
) -> jstring {
    match r_get_base_tx(env, txid, index as u32) {
        Ok(tx) => tx,
        Err(_) => convert_string_to_jstring(env, Error::InvalidTransaction.into()),
    }
}

// Construct a base transaction
pub fn r_get_base_tx(env: JNIEnv, txid: JString, index: u32) -> Result<jstring, Error> {
    let mut tx = Transaction {
        version: 2,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };

    let r_txid = c_char_to_r_bytes(env, txid)?;

    if r_txid.len() != 32 {
        return Err(Error::InvalidTxid);
    }
    let txid = hash_rev(H256::from_slice(&r_txid));

    let input = TransactionInput {
        previous_output: OutPoint { txid, index },
        script_sig: Bytes::new(),
        sequence: 0,
        script_witness: vec![],
    };

    tx.inputs.push(input);

    let tx_hex = hex::encode(serialize_with_flags(&tx, SERIALIZE_TRANSACTION_WITNESS));
    Ok(convert_string_to_jstring(env, tx_hex))
}

/// Passing the tx and input[txid + outpoint's index]
///
/// Returns: String.
/// Return the tx hex string.
/// Possible error string returned is `Invalid Tx Input`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_add_1input(
    env: JNIEnv,
    _class: JClass,
    base_tx: JString,
    txid: JString,
    index: jlong,
) -> jstring {
    match r_add_input(env, base_tx, txid, index as u32) {
        Ok(tx) => tx,
        Err(_) => convert_string_to_jstring(env, Error::InvalidTxInput.into()),
    }
}

pub fn r_add_input(
    env: JNIEnv,
    base_tx: JString,
    txid: JString,
    index: u32,
) -> Result<jstring, Error> {
    let base_tx: String = env
        .get_string(base_tx)
        .map_err(|_| Error::InvalidTxInput)?
        .into();

    let mut base_tx: Transaction = base_tx.parse().map_err(|_| Error::InvalidTransaction)?;

    let r_txid = c_char_to_r_bytes(env, txid)?;

    if r_txid.len() != 32 {
        return Err(Error::InvalidTxid);
    }

    let txid = hash_rev(H256::from_slice(&r_txid));

    let input = TransactionInput {
        previous_output: OutPoint { txid, index },
        script_sig: Bytes::new(),
        sequence: 0,
        script_witness: vec![],
    };

    base_tx.inputs.push(input);
    let tx_hex = hex::encode(serialize_with_flags(
        &base_tx,
        SERIALIZE_TRANSACTION_WITNESS,
    ));
    Ok(convert_string_to_jstring(env, tx_hex))
}

/// Passing the tx and output[address + amount]
///
/// Returns: String.
/// Return the tx hex string.
/// Possible error string returned is `Invalid Tx Output`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_add_1output(
    env: JNIEnv,
    _class: JClass,
    base_tx: JString,
    address: JString,
    amount: jlong,
) -> jstring {
    match r_add_output(env, base_tx, address, amount as u64) {
        Ok(tx) => tx,
        Err(_) => convert_string_to_jstring(env, Error::InvalidTxOutput.into()),
    }
}

pub fn r_add_output(
    env: JNIEnv,
    base_tx: JString,
    addr: JString,
    value: u64,
) -> Result<jstring, Error> {
    let base_tx: String = env
        .get_string(base_tx)
        .map_err(|_| Error::InvalidTxInput)?
        .into();

    let mut base_tx: Transaction = base_tx.parse().map_err(|_| Error::InvalidTransaction)?;

    let address: String = env
        .get_string(addr)
        .map_err(|_| Error::InvalidTxOutput)?
        .into();

    let script_pubkey: Bytes = if value > 0 {
        let addr: Address = address.parse().map_err(|_| Error::InvalidAddress)?;
        Builder::build_address_types(&addr).into()
    } else {
        Builder::build_nulldata(&hex::decode(address)?).into()
    };

    let output = TransactionOutput {
        value,
        script_pubkey,
    };
    base_tx.outputs.push(output);
    let tx_hex = hex::encode(serialize_with_flags(
        &base_tx,
        SERIALIZE_TRANSACTION_WITNESS,
    ));
    Ok(convert_string_to_jstring(env, tx_hex))
}

/// Passing the previous transaction and the constructed transaction
/// and the previous transaction outpoint index to calculate Sighash.
/// agg_pubkey: required when spending by script, pass in a null value when spending by path
/// sigversion: 0 or 1, 0 is Taproot, 1 is Tapscript.
/// Returns: String.
/// Return the sighash.
/// Possible error string returned is `Compute Sighash Fail`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_get_1sighash(
    env: JNIEnv,
    _class: JClass,
    prev_tx: JString,
    tx: JString,
    index: jlong,
    agg_pubkey: JString,
    sigversion: jlong,
) -> jstring {
    match r_get_sighash(env, prev_tx, tx, index as usize, agg_pubkey, sigversion) {
        Ok(tx) => tx,
        Err(_) => convert_string_to_jstring(env, Error::ComputeSighashFail.into()),
    }
}

// Compute a signature hash for schnorr
pub fn r_get_sighash(
    env: JNIEnv,
    prev_tx: JString,
    tx: JString,
    input_index: usize,
    agg_pubkey: JString,
    sigversion: jlong,
) -> Result<jstring, Error> {
    let prev_tx: String = env
        .get_string(prev_tx)
        .map_err(|_| Error::InvalidTxInput)?
        .into();

    let tx: String = env
        .get_string(tx)
        .map_err(|_| Error::InvalidTxInput)?
        .into();

    let prev_tx: Transaction = prev_tx.parse().map_err(|_| Error::InvalidTransaction)?;
    let tx: Transaction = tx.parse().map_err(|_| Error::InvalidTransaction)?;

    let signer: TransactionInputSigner = tx.clone().into();
    let mut execdata = ScriptExecutionData::default();

    let pre_index = tx.inputs[input_index].previous_output.index as usize;

    let sighash = if sigversion == 1 {
        let agg_pubkey = c_char_to_r_bytes(env, agg_pubkey)?;
        if agg_pubkey.len() != 65 {
            return Err(Error::InvalidPublicBytes);
        }
        let agg_pubkey = PublicKey::parse_slice(&agg_pubkey)?;
        let script_pubkey = Builder::default()
            .push_bytes(&agg_pubkey.x_coor().to_vec())
            .push_opcode(Opcode::OP_CHECKSIG)
            .into_script();

        execdata.with_script(&script_pubkey);
        signer.signature_hash_schnorr(
            input_index,
            &[prev_tx.outputs[pre_index].clone()],
            SignatureVersion::TapScript,
            0,
            &execdata,
        )
    } else if sigversion == 0 {
        signer.signature_hash_schnorr(
            input_index,
            &[prev_tx.outputs[pre_index].clone()],
            SignatureVersion::Taproot,
            0,
            &execdata,
        )
    } else {
        return Err(Error::InvalidSigversion);
    };
    let sighash_hex = hex::encode(&sighash);
    Ok(convert_string_to_jstring(env, sighash_hex))
}

/// Construct Threshold address spending transaction.
///
/// [`base_tx`]: tx with at least one input and one output.
/// [`agg_signature`]: aggregate signature of sighash
/// [`agg_pubkey`]: signature corresponding to the aggregate public key.
/// [`control`]: control script.
/// [`input_index`]: index of the input in base_tx.
///
/// Returns: String.
/// Return the tx hex string.
/// Possible error string returned is `Construct Tx Fail`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_build_1raw_1scirpt_1tx(
    env: JNIEnv,
    _class: JClass,
    base_tx: JString,
    agg_signature: JString,
    agg_pubkey: JString,
    control: JString,
    input_index: jlong,
) -> jstring {
    match r_build_raw_scirpt_tx(
        env,
        base_tx,
        agg_signature,
        agg_pubkey,
        control,
        input_index as usize,
    ) {
        Ok(tx) => tx,
        Err(_) => convert_string_to_jstring(env, Error::ConstructTxFail.into()),
    }
}

pub fn r_build_raw_scirpt_tx(
    env: JNIEnv,
    base_tx: JString,
    agg_signature: JString,
    agg_pubkey: JString,
    control: JString,
    input_index: usize,
) -> Result<jstring, Error> {
    let base_tx: String = env
        .get_string(base_tx)
        .map_err(|_| Error::InvalidTxInput)?
        .into();
    let mut base_tx: Transaction = base_tx.parse().map_err(|_| Error::InvalidTransaction)?;

    let agg_signature: Bytes = c_char_to_r_bytes(env, agg_signature)?.into();
    let control: Bytes = c_char_to_r_bytes(env, control)?.into();
    let agg_pubkey = c_char_to_r_bytes(env, agg_pubkey)?;

    if agg_signature.len() != 64 {
        return Err(Error::InvalidSignature);
    }
    if agg_pubkey.len() != 65 {
        return Err(Error::InvalidPublicBytes);
    }

    let pubkey = PublicKey::parse_slice(&agg_pubkey)?;

    let script = Builder::default()
        .push_bytes(&pubkey.x_coor().to_vec())
        .push_opcode(Opcode::OP_CHECKSIG)
        .into_script();

    base_tx.inputs[input_index]
        .script_witness
        .push(agg_signature);
    base_tx.inputs[input_index]
        .script_witness
        .push(script.to_bytes());
    base_tx.inputs[input_index].script_witness.push(control);
    let tx_hex = hex::encode(serialize_with_flags(
        &base_tx,
        SERIALIZE_TRANSACTION_WITNESS,
    ));
    Ok(convert_string_to_jstring(env, tx_hex))
}

/// Construct normal taproot address spending transaction.
///
/// [`base_tx`]: tx with at least one input and one output.
/// [`signature`]: signature of sighash
/// [`input_index`]: index of the input in base_tx.
///
/// Returns: String.
/// Return the tx hex string.
/// Possible error string returned is `Construct Tx Fail`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_build_1raw_1key_1tx(
    env: JNIEnv,
    _class: JClass,
    base_tx: JString,
    signature: JString,
    input_index: jlong,
) -> jstring {
    match r_build_raw_key_tx(env, base_tx, signature, input_index as usize) {
        Ok(tx) => tx,
        Err(_) => convert_string_to_jstring(env, Error::ConstructTxFail.into()),
    }
}

pub fn r_build_raw_key_tx(
    env: JNIEnv,
    base_tx: JString,
    signature: JString,
    input_index: usize,
) -> Result<jstring, Error> {
    let base_tx: String = env
        .get_string(base_tx)
        .map_err(|_| Error::InvalidTransaction)?
        .into();
    let mut base_tx: Transaction = base_tx.parse().map_err(|_| Error::InvalidTransaction)?;

    let signature: Bytes = c_char_to_r_bytes(env, signature)?.into();

    if signature.len() != 64 {
        return Err(Error::InvalidSignature);
    }

    base_tx.inputs[input_index].script_witness.push(signature);

    let tx_hex = hex::encode(serialize_with_flags(
        &base_tx,
        SERIALIZE_TRANSACTION_WITNESS,
    ));
    Ok(convert_string_to_jstring(env, tx_hex))
}

/// Generate schnorr signature.
///
/// [`message`]: waiting for signed message.
/// [`privkey`]: private key
/// [`aux`]: auxiliary random data.
///
/// Returns: String.
/// Return the signature hex string.
/// Possible error string returned is `Invalid Signature`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_generate_1schnorr_1signature(
    env: JNIEnv,
    _class: JClass,
    message: JString,
    privkey: JString,
) -> jstring {
    match r_generate_schnorr_signature(env, message, privkey) {
        Ok(d) => d,
        Err(_) => convert_string_to_jstring(env, Error::InvalidSignature.into()),
    }
}

pub fn r_generate_schnorr_signature(
    env: JNIEnv,
    message: JString,
    privkey: JString,
) -> Result<jstring, Error> {
    let mut key: [u8; 32] = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let aux = H256::from_slice(&key);
    let message = H256::from_slice(&c_char_to_r_bytes(env, message)?);
    let privkey = secp256k1::SecretKey::parse_slice(&c_char_to_r_bytes(env, privkey)?)
        .map_err(|_| Error::InvalidSecret)?;
    let signature: [u8; 64] = sign_with_aux(message, aux, privkey)
        .map_err(|_| Error::InvalidSignature)?
        .into();
    let sig = hex::encode(signature);
    Ok(convert_string_to_jstring(env, sig))
}

/// Generate private key from mnemonic
///
/// [`phrase`]: root phrase
/// [`pd_passphrase`]: pass phrase
///
/// Returns: String.
/// Return the private key hex string.
/// Possible error string returned is `Construct Secret Key`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_get_1my_1privkey(
    env: JNIEnv,
    _class: JClass,
    phrase: JString,
    pd_passphrase: JString,
) -> jstring {
    match r_get_my_privkey(env, phrase, pd_passphrase) {
        Ok(d) => d,
        Err(_) => convert_string_to_jstring(env, Error::InvalidSecret.into()),
    }
}

pub fn r_get_my_privkey(
    env: JNIEnv,
    phrase: JString,
    pd_passphrase: JString,
) -> Result<jstring, Error> {
    let phrase: String = env
        .get_string(phrase)
        .map_err(|_| Error::InvalidPhrase)?
        .into();
    let pd_passphrase: String = env
        .get_string(pd_passphrase)
        .map_err(|_| Error::InvalidPhrase)?
        .into();
    let m = Mnemonic::from_str(&phrase).map_err(|_| Error::InvalidPhrase)?;
    let seed = m.to_seed(&pd_passphrase);
    let privkey = &seed[..32];
    let c_tx_str = hex::encode(privkey);
    Ok(convert_string_to_jstring(env, c_tx_str))
}

/// Generate scirpt pubkey from address
///
/// [`addr`]: input address
///
/// Returns: String.
/// Return the scirpt pubkey hex string.
/// Possible error string returned is `Invalid Address`.
#[no_mangle]
pub extern "system" fn Java_com_chainx_musig2_Transaction_get_1scirpt_1pubkey(
    env: JNIEnv,
    _class: JClass,
    addr: JString,
) -> jstring {
    match r_get_scirpt_pubkey(env, addr) {
        Ok(d) => d,
        Err(_) => convert_string_to_jstring(env, Error::InvalidAddress.into()),
    }
}

pub fn r_get_scirpt_pubkey(env: JNIEnv, addr: JString) -> Result<jstring, Error> {
    let addr: String = env
        .get_string(addr)
        .map_err(|_| Error::InvalidAddress)?
        .into();
    let addr: Address = addr.parse().map_err(|_| Error::InvalidAddress)?;
    let scirpt_pubkey: Bytes = Builder::build_address_types(&addr).into();
    let c_tx_str = hex::encode(&scirpt_pubkey);
    Ok(convert_string_to_jstring(env, c_tx_str))
}
