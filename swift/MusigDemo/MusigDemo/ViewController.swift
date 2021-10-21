//
//  ViewController.swift
//  MusigDemo
//
//  Created by daiwei on 2021/9/30.
//

import UIKit
import Musig

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        let phrase0 = "flame flock chunk trim modify raise rough client coin busy income smile"
        let phrase1 = "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics"
        let phrase2 = "awesome beef hill broccoli strike poem rebel unique turn circle cool system"
        let private0 = getMyPrivkey(phrase: phrase0)
        let private1 = getMyPrivkey(phrase: phrase1)
        let private2 = getMyPrivkey(phrase: phrase2)
        var musig0 = getMusig(priv: private0)
        let musig1 = getMusig(priv: private1)
        let musig2 = getMusig(priv: private2)
        let pubkey0 = getMyPubkey(priv: private0)
        let pubkey1 = getMyPubkey(priv: private1)
        let pubkey2 = getMyPubkey(priv: private2)
        let reveal0 = getMyReveal(musig: musig0)
        let reveal1 = getMyReveal(musig: musig1)
        let reveal2 = getMyReveal(musig: musig2)
        // Reveal stage object serialization
        let musig0_reveal_stage = encodeRevealStage(musig: musig0);
        // Reveal stage object deserialization
        musig0 = decodeRevealStage(reveal_stage: musig0_reveal_stage)
        let cosign0 = getMyCosign(musig: musig0, reveals: [reveal1, reveal2], pubkeys: [pubkey1, pubkey2])
        let cosign1 = getMyCosign(musig: musig1, reveals: [reveal0, reveal2], pubkeys: [pubkey0, pubkey2])
        let cosign2 = getMyCosign(musig: musig2, reveals: [reveal0, reveal1], pubkeys: [pubkey0, pubkey1])
        let signature = getAggSignature(reveals: [reveal0, reveal1, reveal2], cosigns: [cosign0, cosign1, cosign2], pubkeys: [pubkey0, pubkey1, pubkey2])
        let pubkey = getAggPublicKey(pubkeys: [pubkey0, pubkey1, pubkey2])
        print("signature:", signature)
        print("pubkey:", pubkey)
        let pubkeya = "005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d"
        let pubkeyb = "90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547"
        let pubkeyc = "66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415"
        let pubkeyab = "7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861"
        let threshold_pubkey = generateThresholdPubkey(pubkeys: [pubkeya, pubkeyb, pubkeyc], threshold: 2);
        let control_block = generateControlBlock(pubkeys: [pubkeya, pubkeyb, pubkeyc], threshold: 2, agg_pubkey: pubkeyab)
        print("threshold_pubkey:", threshold_pubkey)
        print("control_block:", control_block)
    }


}

