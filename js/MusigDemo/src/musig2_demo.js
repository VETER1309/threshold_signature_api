const {
    getMyKeypair,
    getMyPubkey,
    getAggregationKey,
    getRound1State,
    getRound1Msg,
    getRound2State,
    getRound2R,
    getRound2Msg,
    getSignature,
} = require('musig2');

const privateA = "5495822c4f8efbe17b9bae42a85e8998baec458f3824440d1ce8d9357ad4a7b7"
const privateB = "cef4bbc9689812098c379bec0bb063a895916008344ca04cddbd21ccbcce3bcf"
const privateC = "c9045032eb6df7ebc51d862f9a6a8ffa90eb691dc1b70b4c7b8d1ed0fd8cc25f"

const keypairA = getMyKeypair(privateA)
const keypairB = getMyKeypair(privateB)
const keypairC = getMyKeypair(privateC)

const pubkeyA = getMyPubkey(keypairA)
const pubkeyB = getMyPubkey(keypairB)
const pubkeyC = getMyPubkey(keypairC)

const pubkeys = [pubkeyA, pubkeyB, pubkeyC]
const aggPubkey = getAggregationKey(pubkeys)

const round1StateA = getRound1State(keypairA)
const round1StateB = getRound1State(keypairB)
const round1StateC = getRound1State(keypairC)

const round1MsgA = getRound1Msg(round1StateA)
const round1MsgB = getRound1Msg(round1StateB)
const round1MsgC = getRound1Msg(round1StateC)

const msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38"

const round2StateA = getRound2State(round1StateA, msg, pubkeyA, pubkeys, [round1MsgB, round1MsgC])
const round2StateB = getRound2State(round1StateB, msg, pubkeyB, pubkeys, [round1MsgA, round1MsgC])
const round2StateC = getRound2State(round1StateC, msg, pubkeyC, pubkeys, [round1MsgA, round1MsgB])

const round2RA = getRound2R(round2StateA)
const round2RB = getRound2R(round2StateB)
const round2RC = getRound2R(round2StateC)

const round2MsgA = getRound2Msg(round2StateA)
const round2MsgB = getRound2Msg(round2StateB)
const round2MsgC = getRound2Msg(round2StateC)

const sig = getSignature(round2StateA, [round2MsgB, round2MsgC], round2RA)

console.log(sig)