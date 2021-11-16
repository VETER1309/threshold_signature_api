const ffi = require('ffi-napi');

const lib_path = __dirname + "/libmusig2_dll"
const lib = ffi.Library(lib_path, {
    get_my_pubkey: ['string', ['string']],
    get_round1_state: ['pointer', []],
    encode_round1_state: ['string', ['pointer']],
    decode_round1_state: ['pointer', ['string']],
    get_round1_msg: ['string', ['pointer']],
    get_round2_msg: ['string', ['pointer', 'string', 'string', 'string', 'string']],
    get_signature: ['string', ['string']],
    get_key_agg: ['string', ['string']],
    generate_threshold_pubkey: ['string', ['string', 'uint8', 'string']],
    generate_control_block: ['string', ['string', 'uint8', 'string']],
    get_base_tx: ['string', ['string', 'uint32']],
    add_input: ['string', ['string', 'string', 'uint32']],
    add_output: ['string', ['string', 'string', 'uint64']],
    get_sighash: ['string', ['string', 'string', 'uint32', 'string', 'uint32']],
    build_raw_scirpt_tx: ['string', ['string', 'string', 'string', 'string', 'uint32']],
    build_raw_key_tx: ['string', ['string', 'string', 'uint32']],
    generate_schnorr_signature: ['string', ['string', 'string']],
    get_my_privkey: ['string', ['string', 'string']],
    get_scirpt_pubkey: ['string', ['string', 'string']],
});

getMyPubkey = function (priv) {
    return lib.get_my_pubkey(priv)
}

getAggPublicKey = function (pubkeys) {
    return lib.get_key_agg(pubkeys.join(""))
}

getRound1State = function () {
    return lib.get_round1_state()
}

encodeRound1State = function (round1State) {
    return lib.encode_round1_state(round1State)
}

decodeRound1State = function (round1State) {
    return lib.decode_round1_state(round1State)
}

getRound1Msg = function (round1State) {
    return lib.get_round1_msg(round1State)
}

getRound2Msg = function (round1State, message, privkey, pubkeys, receivedRound1Msgs) {
    return lib.get_round2_msg(round1State, message, privkey, pubkeys.join(""), receivedRound1Msgs.join(""))
}

getAggSignature = function (receivedRound2Msgs) {
    return lib.get_signature(receivedRound2Msgs.join(""))
}

generateThresholdPubkey = function (pubkeys, threshold, network) {
    return lib.generate_threshold_pubkey(pubkeys.join(""), threshold, network)
}

generateControlBlock = function (pubkeys, threshold, aggPubkey) {
    return lib.generate_control_block(pubkeys.join(""), threshold, aggPubkey)
}

getMyPrivkey = function (phrase, pd_passphrase) {
    return lib.get_my_privkey(phrase, pd_passphrase)
}

generateSchnorrSignature = function (message, privkey) {
    return lib.generate_schnorr_signature(message, privkey)
}

getScriptPubkey = function (addr) {
    return lib.get_scirpt_pubkey(addr)
}

generateRawTx = function (txids, indexs, addresses, amounts) {
    let i;
    if (txids.length !== indexs.length){
        return "txids and indexs must be equal in length";
    }
    if (addresses.length !== amounts.length){
        return "addresses and amounts must be equal in length";
    }
    if (txids.length === 0){
        return "Input count must be greater than 0";
    }
    if (addresses.length === 0){
        return "Output count must be greater than 0";
    }
    let base_tx = lib.get_base_tx(txids[0], indexs[0]);
    for (i = 1; i<txids.length; i++){
        base_tx = lib.add_input(base_tx, txids[i], indexs[i]);
    }
    for (i = 0; i<addresses.length; i++){
        base_tx = lib.add_output(base_tx, addresses[i], amounts[i]);
    }
    return base_tx;
}

getSighash = function (prev_tx, tx, input_index, agg_pubkey, sigversion) {
    return lib.get_sighash(prev_tx, tx, input_index, agg_pubkey, sigversion)
}

buildThresholdTx = function (tx, agg_signature, agg_pubkey, control, input_index) {
    return lib.build_raw_scirpt_tx(tx, agg_signature, agg_pubkey, control, input_index)
}

buildTaprootTx = function (tx, signature, input_index) {
    return lib.build_raw_key_tx(tx, signature, input_index)
}

module.exports = {
    getMyPubkey,
    getAggPublicKey,
    getRound1State,
    encodeRound1State,
    decodeRound1State,
    getRound1Msg,
    getRound2Msg,
    getAggSignature,
    generateThresholdPubkey,
    generateControlBlock,
    getMyPrivkey,
    generateSchnorrSignature,
    generateRawTx,
    getSighash,
    buildThresholdTx,
    buildTaprootTx,
}