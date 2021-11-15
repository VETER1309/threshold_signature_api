mod error;

use std::{
    ffi::{CStr, CString},
    ptr::null_mut,
};

use self::error::Error;
use libc::c_char;
use light_bitcoin::{
    chain::{Bytes, OutPoint, Transaction, TransactionInput, TransactionOutput, H256},
    keys::Address,
    mast::Mast,
    primitives::hash_rev,
    script::{
        Builder, Opcode, Script, ScriptExecutionData, SignatureVersion, TransactionInputSigner,
    },
    serialization::{serialize_with_flags, SERIALIZE_TRANSACTION_WITNESS},
};
use musig2::{sign_double_prime, KeyAgg, KeyPair, Nv, PrivateKey, PublicKey, State, StatePrime};

const PUBLICKEY_NORMAL_SIZE: usize = 65;
const ROUND1_MSG_SIZE: usize = Nv * PUBLICKEY_NORMAL_SIZE;
const STATE_PRIME_SIZE: usize = 97;

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
    if secret_bytes.len() != 32 {
        return Err(Error::NormalError);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&secret_bytes[..]);
    let pubkey = PublicKey::create_from_private_key(&PrivateKey::parse(&bytes)?);
    bytes_to_c_char(pubkey.serialize().to_vec())
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
    Ok(bytes_to_c_char(key_agg_bytes.to_vec())?)
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

    let msg: Vec<[u8; 65]> = state
        .our_reveals()
        .iter()
        .map(|eph_key| eph_key.serialize())
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
    message: *const c_char,
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
    message: *const c_char,
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
    let (message, pubkeys, received_round1_msg, keypair) =
        round2_state_parse(message, privkey, pubkeys, received_round1_msg)?;

    let round2_state =
        round1_state.sign_prime(&message, &pubkeys, &keypair, received_round1_msg)?;
    Ok(bytes_to_c_char(round2_state.serialize().to_vec())?)
}

pub fn round2_state_parse(
    message: *const c_char,
    privkey: *const c_char,
    pubkeys: *const c_char,
    received_round1_msg: *const c_char,
) -> Result<(Vec<u8>, Vec<PublicKey>, Vec<Vec<PublicKey>>, KeyPair), Error> {
    let message_bytes = c_char_to_r_bytes(message)?;

    let secret_bytes = c_char_to_r_bytes(privkey)?;
    if secret_bytes.len() != 32 {
        return Err(Error::NormalError);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&secret_bytes[..]);
    let keypair = KeyPair::create_from_private_key(&bytes)?;

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

/// Generate threshold signature addresses by passing in
/// all signer public keys and signature thresholds.
///
/// Returns: String. Return the public key of the threshold-signature address.
/// Possible error string returned is `Invalid Public Bytes`.
#[no_mangle]
pub extern "C" fn generate_threshold_pubkey(
    pubkeys: *const c_char,
    threshold: u8,
    network: *const c_char,
) -> *mut c_char {
    match r_generate_tweak_pubkey(pubkeys, threshold as usize, network) {
        Ok(pubkey) => pubkey,
        Err(_) => Error::InvalidPublicBytes.into(),
    }
}

pub fn r_generate_tweak_pubkey(
    pubkeys: *const c_char,
    threshold: usize,
    network: *const c_char,
) -> Result<*mut c_char, Error> {
    let mast = r_get_my_mast(pubkeys, threshold)?;
    let network = unsafe {
        if network.is_null() {
            return Err(Error::NormalError);
        }
        CStr::from_ptr(network)
    };
    let network = network.to_str()?;
    let tweak = mast.generate_address(network)?;
    let c_tweak_str = CString::new(tweak)?;
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
    let mut keys = [0u8; PUBLICKEY_NORMAL_SIZE];
    keys.copy_from_slice(&r_agg_bytes[0..PUBLICKEY_NORMAL_SIZE]);
    let agg = PublicKey::parse(&keys)?;

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

// Construct a base transaction
pub fn r_get_base_tx(txid: *const c_char, index: u32) -> Result<*mut c_char, Error> {
    let mut tx = Transaction {
        version: 2,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };

    let r_txid = c_char_to_r_bytes(txid)?;

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
    let c_tx_str = CString::new(tx_hex)?;
    Ok(c_tx_str.into_raw())
}

pub fn r_add_input(
    base_tx: *const c_char,
    txid: *const c_char,
    index: u32,
) -> Result<*mut c_char, Error> {
    let c_base_tx = unsafe {
        if base_tx.is_null() {
            return Err(Error::InvalidTransaction);
        }

        CStr::from_ptr(base_tx)
    };

    let mut base_tx: Transaction = c_base_tx
        .to_str()?
        .parse()
        .map_err(|_| Error::InvalidTransaction)?;

    let r_txid = c_char_to_r_bytes(txid)?;

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
    let c_tx_str = CString::new(tx_hex)?;
    Ok(c_tx_str.into_raw())
}

pub fn r_add_output(
    base_tx: *const c_char,
    addr: *const c_char,
    value: u64,
) -> Result<*mut c_char, Error> {
    let c_base_tx = unsafe {
        if addr.is_null() {
            return Err(Error::InvalidAddr);
        }
        CStr::from_ptr(base_tx)
    };

    let mut base_tx: Transaction = c_base_tx
        .to_str()?
        .parse()
        .map_err(|_| Error::InvalidTransaction)?;

    let script_pubkey: Bytes = if value > 0 {
        let c_addr = unsafe {
            if addr.is_null() {
                return Err(Error::InvalidAddr);
            }
            CStr::from_ptr(addr)
        };
        let r_addr = c_addr.to_str()?;
        let addr: Address = r_addr.parse().map_err(|_| Error::InvalidAddr)?;
        Builder::build_address_types(&addr).into()
    } else {
        Builder::build_nulldata(&c_char_to_r_bytes(addr)?).into()
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
    let c_tx_str = CString::new(tx_hex)?;
    Ok(c_tx_str.into_raw())
}

// Compute a signature hash for schnorr
pub fn r_get_sighash(
    prev_tx: *const c_char,
    tx: *const c_char,
    input_index: usize,
    sigversion: u32,
) -> Result<*mut c_char, Error> {
    let (c_prev_tx, c_tx) = unsafe {
        if prev_tx.is_null() || tx.is_null() {
            return Err(Error::InvalidTransaction);
        }

        (CStr::from_ptr(prev_tx), CStr::from_ptr(tx))
    };

    let prev_tx: Transaction = c_prev_tx
        .to_str()?
        .parse()
        .map_err(|_| Error::InvalidTransaction)?;
    let tx: Transaction = c_tx
        .to_str()?
        .parse()
        .map_err(|_| Error::InvalidTransaction)?;

    let signer: TransactionInputSigner = tx.into();
    let mut execdata = ScriptExecutionData::default();
    let sighash = if sigversion == 1 {
        let script_pubkey: Script = prev_tx.outputs[input_index].script_pubkey.clone().into();
        if !script_pubkey.is_pay_to_witness_taproot() {
            return Err(Error::InvalidTaprootScript);
        }
        execdata.with_script(&script_pubkey);
        signer.signature_hash_schnorr(
            input_index,
            &[prev_tx.outputs[input_index].clone()],
            SignatureVersion::TapScript,
            0,
            &execdata,
        )
    } else if sigversion == 0 {
        signer.signature_hash_schnorr(
            input_index,
            &[prev_tx.outputs[input_index].clone()],
            SignatureVersion::Taproot,
            0,
            &execdata,
        )
    } else {
        return Err(Error::InvalidSigversion);
    };
    let sighash_hex = hex::encode(&sighash);
    let c_sighash_str = CString::new(sighash_hex)?;
    Ok(c_sighash_str.into_raw())
}

pub fn r_build_raw_scirpt_tx(
    base_tx: *const c_char,
    agg_signature: *const c_char,
    agg_pubkey: *const c_char,
    control: *const c_char,
    input_index: usize,
) -> Result<*mut c_char, Error> {
    let c_base_tx = unsafe {
        if base_tx.is_null() {
            return Err(Error::InvalidTransaction);
        }
        CStr::from_ptr(base_tx)
    };
    let mut base_tx: Transaction = c_base_tx
        .to_str()?
        .parse()
        .map_err(|_| Error::InvalidTransaction)?;

    let agg_signature: Bytes = c_char_to_r_bytes(agg_signature)?.into();
    let control: Bytes = c_char_to_r_bytes(control)?.into();
    let agg_pubkey = c_char_to_r_bytes(agg_pubkey)?;

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
    let c_tx_str = CString::new(tx_hex)?;
    Ok(c_tx_str.into_raw())
}

pub fn r_build_raw_key_tx(
    base_tx: *const c_char,
    signature: *const c_char,
    input_index: usize,
) -> Result<*mut c_char, Error> {
    let c_base_tx = unsafe {
        if base_tx.is_null() {
            return Err(Error::InvalidTransaction);
        }
        CStr::from_ptr(base_tx)
    };
    let mut base_tx: Transaction = c_base_tx
        .to_str()?
        .parse()
        .map_err(|_| Error::InvalidTransaction)?;

    let signature: Bytes = c_char_to_r_bytes(signature)?.into();

    if signature.len() != 64 {
        return Err(Error::InvalidSignature);
    }

    base_tx.inputs[input_index].script_witness.push(signature);

    let tx_hex = hex::encode(serialize_with_flags(
        &base_tx,
        SERIALIZE_TRANSACTION_WITNESS,
    ));
    let c_tx_str = CString::new(tx_hex)?;
    Ok(c_tx_str.into_raw())
}

#[cfg(test)]
mod tests {
    use musig2::{verify, Signature};
    use std::convert::TryFrom;

    use super::*;
    use secp256k1::Message;

    const PRIVATEA: &str = "e5bb018d70c6fb5dd8ad91f6c88fb0e6fdab2c482978c95bb3794ca6e2e50dc2";
    const PRIVATEB: &str = "a7150e8f24ab26ebebddd831aeb8f00ecb593df3b80ae1e8b8be01351805f2d6";
    const PRIVATEC: &str = "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40";
    const MESSAGE: &str = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38";
    const WITHDRAW_SCRIPT_TX_PREV: &str = "02000000000101aeee49e0bbf7a36f78ea4321b5c8bae0b8c72bdf2c024d2484b137fa7d0f8e1f01000000000000000003a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bb0000000000000000326a3035516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38801a060000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01409e325889515ed47099fdd7098e6fafdc880b21456d3f368457de923f4229286e34cef68816348a0581ae5885ede248a35ac4b09da61a7b9b90f34c200872d2e300000000";
    const WITHDRAW_SCRIPT_TX: &str = "020000000001015fea22ec1a3e3e7e1167fa220cc8376225f07bd20aa194e7f3c4ac68c7375d8e0000000000000000000250c3000000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f409c0000000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bb03402639d4d9882f6e7e42db38dbd2845c87b131737bf557643ef575c49f8fc6928869d9edf5fd61606fb07cced365fdc2c7b637e6ecc85b29906c16d314e7543e94222086a60c7d5dd3f4931cc8ad77a614402bdb591c042347c89281c48c7e9439be9dac61c0e56a1792f348690cdeebe60e3db6c4e94d94e742c619f7278e52f6cbadf5efe96a528ba3f61a5b0d4fbceea425a9028381458b32492bccc3f1faa473a649e23605554f5ea4b4044229173719228a35635eeffbd8a8fe526270b737ad523b99f600000000";
    const WITHDRAW_KEY_TX_PREV: &str = "020000000001014be640313b023c3c731b7e89c3f97bebcebf9772ea2f7747e5604f4483a447b601000000000000000002a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bbc027090000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01404dc68b31efc1468f84db7e9716a84c19bbc53c2d252fd1d72fa6469e860a74486b0990332b69718dbcb5acad9d48634d23ee9c215ab15fb16f4732bed1770fdf00000000";
    const WITHDRAW_KEY_TX: &str = "02000000000101aeee49e0bbf7a36f78ea4321b5c8bae0b8c72bdf2c024d2484b137fa7d0f8e1f01000000000000000003a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bb0000000000000000326a3035516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38801a060000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01409e325889515ed47099fdd7098e6fafdc880b21456d3f368457de923f4229286e34cef68816348a0581ae5885ede248a35ac4b09da61a7b9b90f34c200872d2e300000000";

    fn convert_char_to_str(c: *mut c_char) -> String {
        let c_str = unsafe {
            assert!(!c.is_null());

            CStr::from_ptr(c)
        };
        c_str.to_str().unwrap().to_owned()
    }

    #[test]
    fn test_multiparty_signing() {
        let privkey_a = CString::new(PRIVATEA).unwrap().into_raw();
        let privkey_b = CString::new(PRIVATEB).unwrap().into_raw();
        let privkey_c = CString::new(PRIVATEC).unwrap().into_raw();
        let msg = CString::new(MESSAGE).unwrap().into_raw();

        let pubkey_a = get_my_pubkey(privkey_a);
        let pubkey_b = get_my_pubkey(privkey_b);
        let pubkey_c = get_my_pubkey(privkey_c);
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

        let round2_msg_a =
            get_round2_msg(round1_state_a, msg, privkey_a, pubkeys, round1_received_a);
        let round2_msg_b =
            get_round2_msg(round1_state_b, msg, privkey_b, pubkeys, round1_received_b);
        let round2_msg_c =
            get_round2_msg(round1_state_c, msg, privkey_c, pubkeys, round1_received_c);

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

    #[test]
    fn generate_mulsig_pubkey_should_work() {
        let pubkey_a = CString::new("0483f579dd2380bd31355d066086e1b4d46b518987c1f8a64d4c0101560280eae2b16f3068e94333e11ee63770936eca9692a25f76012511d38ac30ece20f07dca").unwrap().into_raw();
        let pubkey_b = CString::new("047a0868a14bd18e2e45ff3ad960f892df8d0edd1a5685f0a1dc63c7986d4ad55d47c09531e4f2ca2ae7f9ed80c1f9df2edd8afa19188692724d2bc18c18d98c10").unwrap().into_raw();
        let pubkey_c = CString::new("04c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565faced14acb5172ee19aee5417488fecdda33f4cfea9ff04f250e763e6f7458d5e").unwrap().into_raw();
        let pubkeys = bytes_to_c_char(
            [
                c_char_to_r_bytes(pubkey_a).unwrap(),
                c_char_to_r_bytes(pubkey_b).unwrap(),
                c_char_to_r_bytes(pubkey_c).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let network = CString::new("mainnet").unwrap().into_raw();
        let multi_pubkey = convert_char_to_str(generate_threshold_pubkey(pubkeys, 2, network));
        assert_eq!(
            "bc1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwas6syxhp",
            multi_pubkey
        );
    }

    #[test]
    fn generate_control_block_should_work() {
        let privkey_a = CString::new(PRIVATEA).unwrap().into_raw();
        let privkey_b = CString::new(PRIVATEB).unwrap().into_raw();
        let privkey_c = CString::new(PRIVATEC).unwrap().into_raw();
        let pubkey_a = get_my_pubkey(privkey_a);
        let pubkey_b = get_my_pubkey(privkey_b);
        let pubkey_c = get_my_pubkey(privkey_c);
        let pubkeys = bytes_to_c_char(
            [
                c_char_to_r_bytes(pubkey_a).unwrap(),
                c_char_to_r_bytes(pubkey_b).unwrap(),
                c_char_to_r_bytes(pubkey_c).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let pubkeys_ab = bytes_to_c_char(
            [
                c_char_to_r_bytes(pubkey_a).unwrap(),
                c_char_to_r_bytes(pubkey_b).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let ab_agg = get_key_agg(pubkeys_ab);
        let control =
            hex::encode(&c_char_to_r_bytes(generate_control_block(pubkeys, 2, ab_agg)).unwrap());
        assert_eq!("c0e56a1792f348690cdeebe60e3db6c4e94d94e742c619f7278e52f6cbadf5efe92fdde920fba76c5735f1169a54a713816c99dcacaf2c61442e8f87fec02d1100", control);
    }

    fn generate_signature(privs: Vec<&str>, msg: &str) -> (Signature, KeyAgg) {
        let mut pubkeys = Vec::new();
        let mut keypairs = Vec::new();
        for p in privs {
            let privkey = PrivateKey::try_from(p).unwrap();
            let pubkey = PublicKey::create_from_private_key(&privkey);
            let keypair = KeyPair::create_from_private_key(&privkey.0.b32()).unwrap();
            pubkeys.push(pubkey);
            keypairs.push(keypair);
        }
        let message = hex::decode(msg).unwrap();

        let key_agg = KeyAgg::key_aggregation_n(&pubkeys).unwrap();

        let states: Vec<State> = (0..pubkeys.len())
            .into_iter()
            .map(|_| musig2::sign().unwrap())
            .collect();

        let mut state_primes = Vec::new();
        for i in 0..pubkeys.len() {
            let mut received_round_1: Vec<Vec<PublicKey>> =
                states.iter().map(|s| s.our_reveals()).collect();
            received_round_1.remove(i);

            let state_prime = states[i]
                .sign_prime(&message, &pubkeys, &keypairs[i], received_round_1)
                .unwrap();
            state_primes.push(state_prime);
        }

        let signature = sign_double_prime(&state_primes).unwrap();
        (signature, key_agg)
    }

    #[test]
    fn generate_script_tx_should_work() {
        let txid = CString::new("8e5d37c768acc4f3e794a10ad27bf0256237c80c22fa67117e3e3e1aec22ea5f")
            .unwrap()
            .into_raw();
        let index = 0;
        let base_tx = r_get_base_tx(txid, index).unwrap();

        let addr = CString::new("tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68")
            .unwrap()
            .into_raw();
        let value: f32 = 0.0005 * 100_000_000f32;
        let base_tx = r_add_output(base_tx, addr, value as u64).unwrap();
        let addr = CString::new("tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw")
            .unwrap()
            .into_raw();
        let value: f32 = 0.0004 * 100_000_000f32;
        let base_tx = r_add_output(base_tx, addr, value as u64).unwrap();
        let prev_tx = CString::new(WITHDRAW_SCRIPT_TX_PREV).unwrap().into_raw();
        let input_index = 0;
        let sighash = r_get_sighash(prev_tx, base_tx, input_index, 1).unwrap();

        let msg = convert_char_to_str(sighash);
        let privs = vec![PRIVATEB, PRIVATEC];
        let (signature, key_agg) = generate_signature(privs, &msg);
        assert!(verify(
            &signature,
            &Message::parse_slice(&hex::decode(msg).unwrap()).unwrap(),
            &key_agg.X_tilde,
        )
        .unwrap());

        let privkey_a = CString::new(PRIVATEA).unwrap().into_raw();
        let privkey_b = CString::new(PRIVATEB).unwrap().into_raw();
        let privkey_c = CString::new(PRIVATEC).unwrap().into_raw();

        let pubkey_a = get_my_pubkey(privkey_a);
        let pubkey_b = get_my_pubkey(privkey_b);
        let pubkey_c = get_my_pubkey(privkey_c);
        let pubkeys = bytes_to_c_char(
            [
                c_char_to_r_bytes(pubkey_a).unwrap(),
                c_char_to_r_bytes(pubkey_b).unwrap(),
                c_char_to_r_bytes(pubkey_c).unwrap(),
            ]
            .concat(),
        )
        .unwrap();

        let bc_pubkeys = bytes_to_c_char(
            [
                c_char_to_r_bytes(pubkey_b).unwrap(),
                c_char_to_r_bytes(pubkey_c).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let bc_agg_pubkey = get_key_agg(bc_pubkeys);
        let control = generate_control_block(pubkeys, 2, bc_agg_pubkey);
        // The result of each signature is different
        // let sig = CString::new(hex::encode(signature.serialize())).unwrap().into_raw();
        let sig = CString::new("2639d4d9882f6e7e42db38dbd2845c87b131737bf557643ef575c49f8fc6928869d9edf5fd61606fb07cced365fdc2c7b637e6ecc85b29906c16d314e7543e94").unwrap().into_raw();
        let tx = r_build_raw_scirpt_tx(base_tx, sig, bc_agg_pubkey, control, input_index).unwrap();
        assert_eq!(WITHDRAW_SCRIPT_TX, convert_char_to_str(tx));
    }

    #[test]
    fn generate_key_tx_should_work() {
        let txid = CString::new("1f8e0f7dfa37b184244d022cdf2bc7b8e0bac8b52143ea786fa3f7bbe049eeae")
            .unwrap()
            .into_raw();
        let index = 1;
        let base_tx = r_get_base_tx(txid, index).unwrap();

        let addr = CString::new("tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw")
            .unwrap()
            .into_raw();
        let value: f32 = 0.001 * 100_000_000f32;
        let base_tx = r_add_output(base_tx, addr, value as u64).unwrap();
        let op_return = CString::new("35516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38")
            .unwrap()
            .into_raw();
        let value: f32 = 0f32;
        let base_tx = r_add_output(base_tx, op_return, value as u64).unwrap();
        let addr = CString::new("tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68")
            .unwrap()
            .into_raw();
        let value: f32 = 0.004 * 100_000_000f32;
        let base_tx = r_add_output(base_tx, addr, value as u64).unwrap();
        let prev_tx = CString::new(WITHDRAW_KEY_TX_PREV).unwrap().into_raw();
        let input_index = 0;
        let sighash = r_get_sighash(prev_tx, base_tx, input_index, 0).unwrap();

        let msg = convert_char_to_str(sighash);
        let privs = vec![PRIVATEC];
        let (signature, key_agg) = generate_signature(privs, &msg);
        assert!(verify(
            &signature,
            &Message::parse_slice(&hex::decode(msg).unwrap()).unwrap(),
            &key_agg.X_tilde,
        )
        .unwrap());

        // The result of each signature is different
        // let sig = CString::new(hex::encode(signature.serialize())).unwrap().into_raw();
        let sig = CString::new("9e325889515ed47099fdd7098e6fafdc880b21456d3f368457de923f4229286e34cef68816348a0581ae5885ede248a35ac4b09da61a7b9b90f34c200872d2e3").unwrap().into_raw();
        let tx = r_build_raw_key_tx(base_tx, sig, input_index).unwrap();
        assert_eq!(WITHDRAW_KEY_TX, convert_char_to_str(tx));
    }
}
