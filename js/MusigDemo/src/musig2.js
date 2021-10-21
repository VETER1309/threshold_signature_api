const {
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
} = require('musig2');

const privateA = "5495822c4f8efbe17b9bae42a85e8998baec458f3824440d1ce8d9357ad4a7b7"
const privateB = "cef4bbc9689812098c379bec0bb063a895916008344ca04cddbd21ccbcce3bcf"
const privateC = "c9045032eb6df7ebc51d862f9a6a8ffa90eb691dc1b70b4c7b8d1ed0fd8cc25f"
const msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38"

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
let pubkey = getAggPublicKey([round1MsgA, round1MsgB, round1MsgC])

console.log("signature: ", signature)
console.log("pubkey: ", pubkey)

let pubkeyAB = getAggPublicKey([pubkeyA, pubkeyB])
let threshold_pubkey = generateThresholdPubkey([pubkeyA, pubkeyB, pubkeyC], 2);
let control_block = generateControlBlock([pubkeyA, pubkeyB, pubkeyC], 2, pubkeyAB)
console.log("threshold_pubkey:", threshold_pubkey)
console.log("control_block:", control_block)