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
    getMyPrivkey,
    generateSchnorrSignature,
    generateRawTx,
    getSighash,
    buildThresholdTx,
    buildTaprootTx,
} = require('musig2');

const PHRASE0 = "flame flock chunk trim modify raise rough client coin busy income smile";
const PHRASE1 =
    "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics";
const PHRASE2 =
    "awesome beef hill broccoli strike poem rebel unique turn circle cool system";
const msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38"

// Aggregate signature generation
let privateA = getMyPrivkey(PHRASE0,  "")
let privateB = getMyPrivkey(PHRASE1,  "")
let privateC = getMyPrivkey(PHRASE2,  "")
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
console.log(" ", signature)
console.log("pubkey: ", pubkey)

// Use Mast to generate addresses and control blocks
let pubkeyAB = getAggPublicKey([pubkeyA, pubkeyB])
let threshold_pubkey = generateThresholdPubkey([pubkeyA, pubkeyB, pubkeyC], 2, "mainnet");
let control_block = generateControlBlock([pubkeyA, pubkeyB, pubkeyC], 2, pubkeyAB)
console.log("threshold_pubkey:", threshold_pubkey)
console.log("control_block:", control_block)

// Generate taproot tx
const private_char = "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40";
const prev_tx = "020000000001014be640313b023c3c731b7e89c3f97bebcebf9772ea2f7747e5604f4483a447b601000000000000000002a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bbc027090000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01404dc68b31efc1468f84db7e9716a84c19bbc53c2d252fd1d72fa6469e860a74486b0990332b69718dbcb5acad9d48634d23ee9c215ab15fb16f4732bed1770fdf00000000";
let txids = ["1f8e0f7dfa37b184244d022cdf2bc7b8e0bac8b52143ea786fa3f7bbe049eeae"];
let indexs = [1];
let addresses  = ["tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw", "35516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38", "tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68"];
let amounts = [100000, 0, 400000];

let tx = generateRawTx(txids, indexs, addresses, amounts);
let sighash = getSighash(prev_tx, tx, 0,  "", 0);
console.log("sighash:", sighash);
let schnorr_signature = generateSchnorrSignature(sighash, private_char);
console.log("schnorr_signature:", schnorr_signature);
let taproot_tx = buildTaprootTx(tx,  schnorr_signature, 0);
console.log("taproot_tx", taproot_tx);

// Generate Threshold tx
let private_a = "e5bb018d70c6fb5dd8ad91f6c88fb0e6fdab2c482978c95bb3794ca6e2e50dc2";
let private_b = "a7150e8f24ab26ebebddd831aeb8f00ecb593df3b80ae1e8b8be01351805f2d6";
let private_c = "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40";
let prev_tx_1 = "02000000000101aeee49e0bbf7a36f78ea4321b5c8bae0b8c72bdf2c024d2484b137fa7d0f8e1f01000000000000000003a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bb0000000000000000326a3035516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38801a060000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01409e325889515ed47099fdd7098e6fafdc880b21456d3f368457de923f4229286e34cef68816348a0581ae5885ede248a35ac4b09da61a7b9b90f34c200872d2e300000000";
let pubkey_a = getMyPubkey(private_a);
let pubkey_b = getMyPubkey(private_b);
let pubkey_c = getMyPubkey(private_c);
let pubkey_bc = getAggPublicKey([pubkey_b, pubkey_c])
let txids_1 = ["8e5d37c768acc4f3e794a10ad27bf0256237c80c22fa67117e3e3e1aec22ea5f"];
let indexs_1 = [0];
let addresses_1  = ["tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68", "tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw"];
let amounts_1= [50000, 40000];
let tx_1 = generateRawTx(txids_1,  indexs_1, addresses_1, amounts_1);
let sighash_1 = getSighash(prev_tx_1, tx_1, 0,  pubkey_bc, 1);
console.log("sighash_1:", sighash_1);
// Here is the aggregate signature of sighash of two persons b and c
let multi_signature = "2639d4d9882f6e7e42db38dbd2845c87b131737bf557643ef575c49f8fc6928869d9edf5fd61606fb07cced365fdc2c7b637e6ecc85b29906c16d314e7543e94";
let control_1 = generateControlBlock([pubkey_a, pubkey_b, pubkey_c], 2,  pubkey_bc)
let threshold_tx = buildThresholdTx(tx_1, multi_signature,  pubkey_bc, control_1, 0);
console.log("threshold_tx", threshold_tx);

