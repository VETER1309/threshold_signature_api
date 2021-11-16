//
//  ViewController.swift
//  Musig2Demo
//
//  Created by daiwei on 2021/10/16.
//

import UIKit
import Musig2

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.

        // Aggregate signature generation
        let PHRASE0 = "flame flock chunk trim modify raise rough client coin busy income smile";
        let PHRASE1 =
            "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics";
        let PHRASE2 =
            "awesome beef hill broccoli strike poem rebel unique turn circle cool system";
        let msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38"
        let private0 = getMyPrivkey(phrase: PHRASE0, pd_passphrase: "")
        let private1 = getMyPrivkey(phrase: PHRASE1, pd_passphrase: "")
        let private2 = getMyPrivkey(phrase: PHRASE2, pd_passphrase: "")
        var round1_state0 = getRound1State()
        let round1_state1 = getRound1State()
        let round1_state2 = getRound1State()
        let pubkey0 = getMyPubkey(priv: private0)
        let pubkey1 = getMyPubkey(priv: private1)
        let pubkey2 = getMyPubkey(priv: private2)
        let round1_msg0 = getRound1Msg(state: round1_state0)
        let round1_msg1 = getRound1Msg(state: round1_state1)
        let round1_msg2 = getRound1Msg(state: round1_state2)
        let state_str = encodeRound1State(state: round1_state0);
        round1_state0 = decodeRound1State(round1_state: state_str)
        let round2_msg0 = getRound2Msg(state: round1_state0, msg: msg, priv: private0, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg1, round1_msg2])
        let round2_msg1 = getRound2Msg(state: round1_state1, msg: msg, priv: private1, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg0, round1_msg2])
        let round2_msg2 = getRound2Msg(state: round1_state2, msg: msg, priv: private2, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg0, round1_msg1])
        let signature = getAggSignature(round2_msg: [round2_msg0, round2_msg1, round2_msg2])
        let pubkey = getAggPublicKey(pubkeys: [pubkey0, pubkey1, pubkey2])
        print("signature:", signature)
        print("pubkey:", pubkey)

        // Use Mast to generate addresses and control blocks
        let pubkey01 = getAggPublicKey(pubkeys: [pubkey0, pubkey1])
        let threshold_pubkey = generateThresholdPubkey(pubkeys: [pubkey0, pubkey1, pubkey2], threshold: 2, network: "mainnet");
        let control_block = generateControlBlock(pubkeys: [pubkey0, pubkey1, pubkey2], threshold: 2, agg_pubkey: pubkey01)
        print("threshold_pubkey:", threshold_pubkey)
        print("control_block:", control_block)

        // Generate taproot tx
        let private_char = "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40";
        let prev_tx = "020000000001014be640313b023c3c731b7e89c3f97bebcebf9772ea2f7747e5604f4483a447b601000000000000000002a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bbc027090000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01404dc68b31efc1468f84db7e9716a84c19bbc53c2d252fd1d72fa6469e860a74486b0990332b69718dbcb5acad9d48634d23ee9c215ab15fb16f4732bed1770fdf00000000";
        let txids: [String] = ["1f8e0f7dfa37b184244d022cdf2bc7b8e0bac8b52143ea786fa3f7bbe049eeae"];
        let indexs: [UInt32] = [1];
        let addresses: [String]  = ["tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw", "35516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38", "tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68"];
        let amounts: [UInt64] = [100000, 0, 400000];
        let tx = generateRawTx(txids: txids, indexs:indexs, addresses:addresses, amounts: amounts);
        let sighash = getSighash(prev_tx: prev_tx, tx: tx, input_index: 0, agg_pubkey: "", sigversion: 0);
        print("sighash:", sighash);
        let schnorr_signature = generateSchnorrSignature(message: sighash, privkey: private_char);
        print("schnorr_signature:", schnorr_signature);
        let taproot_tx = buildTaprootTx(tx: tx, signature: schnorr_signature, input_index: 0);
        print("taproot_tx", taproot_tx);

        // Generate Threshold tx
        let private_a = "e5bb018d70c6fb5dd8ad91f6c88fb0e6fdab2c482978c95bb3794ca6e2e50dc2";
        let private_b = "a7150e8f24ab26ebebddd831aeb8f00ecb593df3b80ae1e8b8be01351805f2d6";
        let private_c = "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40";
        let prev_tx_1 = "02000000000101aeee49e0bbf7a36f78ea4321b5c8bae0b8c72bdf2c024d2484b137fa7d0f8e1f01000000000000000003a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bb0000000000000000326a3035516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38801a060000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01409e325889515ed47099fdd7098e6fafdc880b21456d3f368457de923f4229286e34cef68816348a0581ae5885ede248a35ac4b09da61a7b9b90f34c200872d2e300000000";
        let pubkey_a = getMyPubkey(priv: private_a);
        let pubkey_b = getMyPubkey(priv: private_b);
        let pubkey_c = getMyPubkey(priv: private_c);
        let pubkey_bc = getAggPublicKey(pubkeys: [pubkey_b, pubkey_c])
        let txids_1: [String] = ["8e5d37c768acc4f3e794a10ad27bf0256237c80c22fa67117e3e3e1aec22ea5f"];
        let indexs_1: [UInt32] = [0];
        let addresses_1: [String]  = ["tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68", "tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw"];
        let amounts_1: [UInt64] = [50000, 40000];
        let tx_1 = generateRawTx(txids: txids_1, indexs: indexs_1, addresses:addresses_1, amounts: amounts_1);
        let sighash_1 = getSighash(prev_tx: prev_tx_1, tx: tx_1, input_index: 0, agg_pubkey: pubkey_bc, sigversion: 1);
        print("sighash_1:", sighash_1);
        // Here is the aggregate signature of sighash of two persons b and c
        let multi_signature = "2639d4d9882f6e7e42db38dbd2845c87b131737bf557643ef575c49f8fc6928869d9edf5fd61606fb07cced365fdc2c7b637e6ecc85b29906c16d314e7543e94";
        let control_1 = generateControlBlock(pubkeys: [pubkey_a, pubkey_b, pubkey_c], threshold: 2, agg_pubkey: pubkey_bc)
        let threshold_tx = buildThresholdTx(tx: tx_1, agg_signature: multi_signature, agg_pubkey: pubkey_bc, control: control_1, input_index: 0);
        print("threshold_tx", threshold_tx);
    }


}

