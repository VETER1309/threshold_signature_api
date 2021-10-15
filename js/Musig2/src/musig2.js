const ffi = require('ffi-napi');

const lib_path = __dirname + "/libmusig2_dll"
const lib = ffi.Library(lib_path, {
    get_my_keypair: ['pointer', ['string']],
    get_my_pubkey: ['string', ['pointer']],
    get_key_agg: ['string', ['string']],
    get_round1_state: ['pointer', ['pointer']],
    get_round1_msg: ['string', ['pointer']],
    get_round2_state: ['pointer', ['pointer', 'string', 'string', 'string', 'string']],
    get_round2_r: ['string', ['pointer']],
    get_round2_msg: ['string', ['pointer']],
    get_signature: ['string', ['pointer', 'string', 'string']],
});

getMyKeypair = function (priv) {
    return lib.get_my_keypair(priv)
}

getMyPubkey = function (keypair) {
    return lib.get_my_pubkey(keypair)
}

getAggregationKey = function (pubkeys) {
    return lib.get_key_agg(pubkeys.join(""))
}

getRound1State = function (keypair) {
    return lib.get_round1_state(keypair)
}

getRound1Msg = function (round1State) {
    return lib.get_round1_msg(round1State)
}

getRound2State = function (round1State, message, myPubkey, pubkeys, receivedRound1Msgs) {
    return lib.get_round2_state(round1State, message, myPubkey, pubkeys.join(""), receivedRound1Msgs.join(""))
}

getRound2R = function (round2State) {
    return lib.get_round2_r(round2State)
}

getRound2Msg = function (round2State) {
    return lib.get_round2_msg(round2State)
}

getSignature = function (round2State, receivedRound2Msgs, R) {
    return lib.get_signature(round2State, receivedRound2Msgs.join(""), R)
}

module.exports = {
    getMyKeypair,
    getMyPubkey,
    getAggregationKey,
    getRound1State,
    getRound1Msg,
    getRound2State,
    getRound2R,
    getRound2Msg,
    getSignature,
}