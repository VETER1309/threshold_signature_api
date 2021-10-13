const ffi = require('ffi-napi');

const lib_path = __dirname + "/libmusig_dll"
const lib = ffi.Library(lib_path, {
    get_my_pubkey: ['string', ['string']],
    get_musig: ['pointer', ['string']],
    get_my_reveal: ['string', ['pointer']],
    encode_reveal_stage: ['string', ['pointer']],
    decode_reveal_stage: ['pointer', ['string']],
    cosign_stage: ['pointer', ['pointer', 'string', 'string']],
    get_my_cosign: ['string', ['pointer']],
    encode_cosign_stage: ['string', ['pointer']],
    decode_cosign_stage: ['pointer', ['string']],
    get_signature: ['string', ['string', 'string', 'string']],
    get_agg_pubkey: ['string', ['string']],
    generate_threshold_pubkey: ['string', ['string', 'uint8']],
    generate_control_block: ['string', ['string', 'uint8', 'string']]
});

getMyMusig = function (priv) {
    return lib.get_musig(priv)
}

getMyPubkey = function (priv) {
    return lib.get_my_pubkey(priv)
}
getMyReveal = function (musig) {
    return lib.get_my_reveal(musig)
}

getMyCosign = function (musig, reveals, pubkeys) {
    musig = lib.cosign_stage(musig, reveals.join(""), pubkeys.join(""))
    return lib.get_my_cosign(musig)
}

encodeRevealStage = function (musig) {
    return lib.encode_reveal_stage(musig)
}

decodeRevealStage = function (musig) {
    return lib.decode_reveal_stage(musig)
}

encodeCosignStage = function (musig) {
    return lib.encode_cosign_stage(musig)
}
decodeCosignStage = function (musig) {
    return lib.encode_cosign_stage(musig)
}

getAggSignature = function (reveals, pubkeys, cosigns) {
    return lib.get_signature(reveals.join(""), pubkeys.join(""), cosigns.join(""))
}

getAggPubkey = function (pubkeys) {
    return lib.get_agg_pubkey(pubkeys.join(""))
}

generateThresholdPubkey = function (pubkeys, threshold) {
    return lib.generate_threshold_pubkey(pubkeys.join(""), threshold)
}

generateControlBlock = function (pubkeys, threshold, aggPubkey) {
    return lib.generate_control_block(pubkeys.join(""), threshold, aggPubkey)
}

module.exports = {
    getMyMusig,
    getMyPubkey,
    getMyReveal,
    getMyCosign,
    encodeRevealStage,
    decodeRevealStage,
    encodeCosignStage,
    decodeCosignStage,
    getAggSignature,
    getAggPubkey,
    generateThresholdPubkey,
    generateControlBlock,
}
