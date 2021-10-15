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
        let private0 = "5495822c4f8efbe17b9bae42a85e8998baec458f3824440d1ce8d9357ad4a7b7"
        let private1 = "cef4bbc9689812098c379bec0bb063a895916008344ca04cddbd21ccbcce3bcf"
        let private2 = "c9045032eb6df7ebc51d862f9a6a8ffa90eb691dc1b70b4c7b8d1ed0fd8cc25f"
        let msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38"
        var round1_state0 = getRound1State(priv: private0)
        let round1_state1 = getRound1State(priv: private1)
        let round1_state2 = getRound1State(priv: private2)
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
        let round2_msg0 = getRound2Msg(state: round1_state0, msg: msg, my_pubkey: pubkey0, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg1, round1_msg2])
        let round2_msg1 = getRound2Msg(state: round1_state1, msg: msg, my_pubkey: pubkey1, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg0, round1_msg2])
        let round2_msg2 = getRound2Msg(state: round1_state2, msg: msg, my_pubkey: pubkey2, pubkeys: [pubkey0, pubkey1, pubkey2], received_round1_msg:[round1_msg0, round1_msg1])
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

