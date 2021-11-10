//
//  ViewController.swift
//  Musig2Sr25519Demo
//
//  Created by daiwei on 2021/10/22.
//

import UIKit
import Musig2Sr25519

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        let phrase0 = "flame flock chunk trim modify raise rough client coin busy income smile"
        let phrase1 = "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics"
        let phrase2 = "awesome beef hill broccoli strike poem rebel unique turn circle cool system"
        let msg: UInt32 = 666666
        let private0 = getMyPrivkey(phrase: phrase0)
        let private1 = getMyPrivkey(phrase: phrase1)
        let private2 = getMyPrivkey(phrase: phrase2)
        var round1_state0 = getRound1State()
        let round1_state1 = getRound1State()
        let round1_state2 = getRound1State()
        let pubkey0 = getMyPubkey(priv: private0)
        let pubkey1 = getMyPubkey(priv: private1)
        let pubkey2 = getMyPubkey(priv: private2)
        let round1_msg0 = getRound1Msg(state: round1_state0)
        let round1_msg1 = getRound1Msg(state: round1_state1)
        let round1_msg2 = getRound1Msg(state: round1_state2)
        // Round1 state object serialization
        let state_str = encodeRound1State(state: round1_state0);
        // Round1 state object deserialization
        round1_state0 = decodeRound1State(round1_state: state_str)
        let round2_msg0 = getRound2Msg(state: round1_state0, msg: msg, priv: private0, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg1, round1_msg2])
        let round2_msg1 = getRound2Msg(state: round1_state1, msg: msg, priv: private1, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg0, round1_msg2])
        let round2_msg2 = getRound2Msg(state: round1_state2, msg: msg, priv: private2, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg0, round1_msg1])
        let signature = getAggSignature(round2_msg: [round2_msg0, round2_msg1, round2_msg2])
        let pubkey = getAggPublicKey(pubkeys: [pubkey0, pubkey1, pubkey2])
        print("signature:", signature)
        print("pubkey:", pubkey)
        
        let pubkey01 = getAggPublicKey(pubkeys: [pubkey0, pubkey1])
        let threshold_pubkey = generateThresholdPubkey(pubkeys: [pubkey0, pubkey1, pubkey2], threshold: 2);
        let control_block = generateControlBlock(pubkeys: [pubkey0, pubkey1, pubkey2], threshold: 2, agg_pubkey: pubkey01)
        print("threshold_pubkey:", threshold_pubkey)
        print("control_block:", control_block)
    }


}

