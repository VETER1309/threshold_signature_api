const ffi = require('ffi');

const lib = ffi.Library('libmusig_dll', {
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
}

Musig.prototype.getMyPubkey = function () {
    return this.pubkey
}

Musig.prototype.getMyCommit = function () {
    this.ptr = lib.get_musig(this.priv)
    this.commit = lib.get_my_commit(this.ptr)
    return this.commit
}

Musig.prototype.getMyReveal = function (commits, pubkeys) {
    let commits_str = this.commit
    let pubkeys_str = this.pubkey
    for (let i = 0; i < commits.length; i++) {
        commits_str += commits[i]
        pubkeys_str += pubkeys[i]
    }
    this.ptr = lib.reveal_stage(this.ptr, commits_str, pubkeys_str)
    this.reveal = lib.get_my_reveal(this.ptr)
    return this.reveal
}

Musig.prototype.getMyCosign = function (reveals, pubkeys) {
    let reveals_str = this.reveal
    let pubkeys_str = this.pubkey
    for (let i = 0; i < reveals.length; i++) {
        reveals_str += reveals[i]
        pubkeys_str += pubkeys[i]
    }
    this.ptr = lib.cosign_stage(this.ptr, reveals_str, pubkeys_str)
    this.cosign = lib.get_my_cosign(this.ptr)
    return this.cosign
}

getAggSignature = function (reveals, pubkeys, cosigns) {
    let reveals_str = ""
    let cosigns_str = ""
    let pubkeys_str = ""
    for (let i = 0; i < reveals.length; i++) {
        reveals_str += reveals[i]
        cosigns_str += cosigns[i]
        pubkeys_str += pubkeys[i]
    }
    return lib.get_signature(reveals_str, pubkeys_str, cosigns_str)
}

getAggPubkey = function (pubkeys) {
    let pubkeys_str = ""
    for (let i = 0; i < pubkeys.length; i++) {
        pubkeys_str += pubkeys[i]
    }
    return lib.get_agg_pubkey(pubkeys_str)
}

const private0 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2"
const private1 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38"
const private2 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59"
const musig0 = new Musig(private0)
const musig1 = new Musig(private1)
const musig2 = new Musig(private2)
const pubkey0 = musig0.getMyPubkey()
const pubkey1 = musig1.getMyPubkey()
const pubkey2 = musig2.getMyPubkey()
const pubkey = getAggPubkey([pubkey0, pubkey1, pubkey2])
const commit0 = musig0.getMyCommit()
const commit1 = musig1.getMyCommit()
const commit2 = musig2.getMyCommit()
const reveal0 = musig0.getMyReveal([commit1, commit2], [pubkey1, pubkey2])
const reveal1 = musig1.getMyReveal([commit0, commit2], [pubkey0, pubkey2])
const reveal2 = musig2.getMyReveal([commit0, commit1], [pubkey0, pubkey1])
const cosign0 = musig0.getMyCosign([reveal1, reveal2], [pubkey1, pubkey2])
const cosign1 = musig1.getMyCosign([reveal0, reveal2], [pubkey0, pubkey2])
const cosign2 = musig2.getMyCosign([reveal0, reveal1], [pubkey0, pubkey1])
const signature = getAggSignature([reveal0, reveal1, reveal2], [pubkey0, pubkey1, pubkey2], [cosign0, cosign1, cosign2])
console.log("pubkey:", pubkey)
console.log("signature:", signature)


