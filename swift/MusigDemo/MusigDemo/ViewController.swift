//
//  ViewController.swift
//  MusigDemo
//
//  Created by daiwei on 2021/9/26.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        let private0 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2"
        let private1 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38"
        let private2 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59"
        let musig0 = Musig(priv: private0)
        let musig1 = Musig(priv: private1)
        let musig2 = Musig(priv: private2)
        let pubkey0 = musig0.getMyPubkey()
        let pubkey1 = musig1.getMyPubkey()
        let pubkey2 = musig2.getMyPubkey()
        let commit0 = musig0.getMyCommit()
        let commit1 = musig1.getMyCommit()
        let commit2 = musig2.getMyCommit()
        let reveal0 = musig0.getMyReveal(commits: [commit1, commit2], pubkeys: [pubkey1, pubkey2])
        let reveal1 = musig1.getMyReveal(commits: [commit0, commit2], pubkeys: [pubkey0, pubkey2])
        let reveal2 = musig2.getMyReveal(commits: [commit0, commit1], pubkeys: [pubkey0, pubkey1])
        let cosign0 = musig0.getMyCosign(reveals: [reveal1, reveal2], pubkeys: [pubkey1, pubkey2])
        let cosign1 = musig1.getMyCosign(reveals: [reveal0, reveal2], pubkeys: [pubkey0, pubkey2])
        let cosign2 = musig2.getMyCosign(reveals: [reveal0, reveal1], pubkeys: [pubkey0, pubkey1])
        let signature = musig0.getAggSignature(reveals: [reveal0, reveal1, reveal2], cosigns: [cosign0, cosign1, cosign2], pubkeys: [pubkey0, pubkey1, pubkey2])
        let pubkey = musig0.getAggPublicKey(pubkeys: [pubkey0, pubkey1, pubkey2])
        print("signature:", signature)
        print("pubkey:", pubkey)
        
    }


}
