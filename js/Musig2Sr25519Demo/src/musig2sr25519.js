const {
    getMyPubkey,
    getMyPrivkey,
    getAggPublicKey,
    getRound1State,
    encodeRound1State,
    decodeRound1State,
    getRound1Msg,
    getRound2Msg,
    getAggSignature,
    generateThresholdPubkey,
    generateControlBlock,
} = require('musig2-sr25519');

const phraseA = "flame flock chunk trim modify raise rough client coin busy income smile"
const phraseB = "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics"
const phraseC = "awesome beef hill broccoli strike poem rebel unique turn circle cool system"
const msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38"

let privateA = getMyPrivkey(phraseA)
let privateB = getMyPrivkey(phraseB)
let privateC = getMyPrivkey(phraseC)

let round1StateA = getRound1State()
let round1StateB = getRound1State()
let round1StateC = getRound1State()

let pubkeyA = getMyPubkey(privateA)
let pubkeyB = getMyPubkey(privateB)
let pubkeyC = getMyPubkey(privateC)

let encodedRound1StateA = encodeRound1State(round1StateA)
round1StateA = decodeRound1State(encodedRound1StateA)

let round1MsgA = getRound1Msg(round1StateA)
let round1MsgB = getRound1Msg(round1StateB)
let round1MsgC = getRound1Msg(round1StateC)

let round2MsgA = getRound2Msg(round1StateA, msg, privateA, [pubkeyA, pubkeyB, pubkeyC], [round1MsgB, round1MsgC])
let round2MsgB = getRound2Msg(round1StateB, msg, privateB, [pubkeyA, pubkeyB, pubkeyC], [round1MsgA, round1MsgC])
let round2MsgC = getRound2Msg(round1StateC, msg, privateC, [pubkeyA, pubkeyB, pubkeyC], [round1MsgB, round1MsgA])

let signature = getAggSignature([round2MsgA, round2MsgB, round2MsgC])
let pubkey = getAggPublicKey([pubkeyA, pubkeyB, pubkeyC])

console.log("signature: ", signature)
console.log("pubkey: ", pubkey)

let pubkeyAB = getAggPublicKey([pubkeyA, pubkeyB])
let threshold_pubkey = generateThresholdPubkey([pubkeyA, pubkeyB, pubkeyC], 2);
let control_block = generateControlBlock([pubkeyA, pubkeyB, pubkeyC], 2, pubkeyAB)
console.log("threshold_pubkey:", threshold_pubkey)
console.log("control_block:", control_block)