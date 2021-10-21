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
    generate_threshold_pubkey: ['string', ['string', 'uint8']],
    generate_control_block: ['string', ['string', 'uint8', 'string']],
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

generateThresholdPubkey = function (pubkeys, threshold) {
    return lib.generate_threshold_pubkey(pubkeys.join(""), threshold)
}

generateControlBlock = function (pubkeys, threshold, aggPubkey) {
    return lib.generate_control_block(pubkeys.join(""), threshold, aggPubkey)
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
}


