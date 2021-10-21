const {
    getMyMusig,
    getMyPubkey,
    getMyPrivkey,
    getMyReveal,
    getMyCosign,
    encodeRevealStage,
    decodeRevealStage,
    getAggSignature,
    getAggPubkey,
    generateThresholdPubkey,
    generateControlBlock,
} = require('musig');

const phrase0 = "flame flock chunk trim modify raise rough client coin busy income smile"
const phrase1 = "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics"
const phrase2 = "awesome beef hill broccoli strike poem rebel unique turn circle cool system"

const private0 = getMyPrivkey(phrase0)
const private1 = getMyPrivkey(phrase1)
const private2 = getMyPrivkey(phrase2)

let musig0 = getMyMusig(private0)
// Reveal stage object serialization
musig0_reveal_stage = encodeRevealStage(musig0)
// Reveal stage object deserialization
musig0 = decodeRevealStage(musig0_reveal_stage)
const musig1 = getMyMusig(private1)
const musig2 = getMyMusig(private2)

const pubkey0 = getMyPubkey(private0)
const pubkey1 = getMyPubkey(private1)
const pubkey2 = getMyPubkey(private2)

const reveal0 = getMyReveal(musig0)
const reveal1 = getMyReveal(musig1)
const reveal2 = getMyReveal(musig2)
const cosign0 = getMyCosign(musig0, [reveal1, reveal2], [pubkey1, pubkey2])
const cosign1 = getMyCosign(musig1, [reveal0, reveal2], [pubkey0, pubkey2])
const cosign2 = getMyCosign(musig2, [reveal0, reveal1], [pubkey0, pubkey1])
const signature = getAggSignature([reveal0, reveal1, reveal2], [pubkey0, pubkey1, pubkey2], [cosign0, cosign1, cosign2])
const pubkey = getAggPubkey([pubkey0, pubkey1, pubkey2])
console.log("pubkey:", pubkey)
console.log("signature:", signature)

const publicA = "005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d"
const publicB = "90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547"
const publicC = "66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415"
const publicAB = "7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861";

const threshold_pubkey = generateThresholdPubkey([publicA, publicB, publicC], 2)
const control = generateControlBlock([publicA, publicB, publicC], 2, publicAB)

console.log("pubkey:", threshold_pubkey)
console.log("control:", control)
