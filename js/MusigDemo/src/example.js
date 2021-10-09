const {Musig, Mast, getAggSignature, getAggPubkey} = require('musig');

const private0 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2"
const private1 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38"
const private2 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59"
const musig0 = new Musig(private0)
const musig1 = new Musig(private1)
const musig2 = new Musig(private2)
const pubkey0 = musig0.getMyPubkey()
const pubkey1 = musig1.getMyPubkey()
const pubkey2 = musig2.getMyPubkey()
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
const pubkey = getAggPubkey([pubkey0, pubkey1, pubkey2])
console.log("pubkey:", pubkey)
console.log("signature:", signature)

const publicA = "005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d"
const publicB = "90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547"
const publicC = "66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415"
const publicAB = "7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861";

const mast = new Mast([publicA, publicB, publicC], 2)
const threshold_pubkey = mast.generateThresholdPubkey()
const control = mast.generateControlBlock(publicAB)

console.log("pubkey:", threshold_pubkey)
console.log("control:", control)
