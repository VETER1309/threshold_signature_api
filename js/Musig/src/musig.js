const ffi = require('ffi-napi');

const lib_path = __dirname + "/libmusig_dll"
const lib = ffi.Library(lib_path, {
    get_my_pubkey: ['string', ['string']],
    get_musig: ['pointer', ['string']],
    get_my_commit: ['string', ['pointer']],
    reveal_stage: ['pointer', ['pointer', 'string', 'string']],
    get_my_reveal: ['string', ['pointer']],
    cosign_stage: ['pointer', ['pointer', 'string', 'string']],
    get_my_cosign: ['string', ['pointer']],
    get_signature: ['string', ['string', 'string', 'string']],
    get_agg_pubkey: ['string', ['string']],
});

const Musig = function (priv) {
    this.priv = priv
    this.pubkey = lib.get_my_pubkey(this.priv)
    this.ptr = lib.get_musig(this.priv)
}

Musig.prototype.getMyPubkey = function () {
    return this.pubkey
}

Musig.prototype.getMyCommit = function () {
    return lib.get_my_commit(this.ptr)
}

Musig.prototype.getMyReveal = function (commits, pubkeys) {
    this.ptr = lib.reveal_stage(this.ptr, commits.join(""), pubkeys.join(""))
    return lib.get_my_reveal(this.ptr)
}

Musig.prototype.getMyCosign = function (reveals, pubkeys) {
    this.ptr = lib.cosign_stage(this.ptr, reveals.join(""), pubkeys.join(""))
    return lib.get_my_cosign(this.ptr)
}

Musig.prototype.getAggSignature = function (reveals, pubkeys, cosigns) {
    return lib.get_signature(reveals.join(""), pubkeys.join(""), cosigns.join(""))
}

Musig.prototype.getAggPubkey = function (pubkeys) {
    return lib.get_agg_pubkey(pubkeys.join(""))
}

module.exports = {
    Musig
}


