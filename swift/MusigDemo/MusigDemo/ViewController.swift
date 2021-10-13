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
        let private0 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2"
        let private1 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38"
        let private2 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59"
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

