//
//  ViewController.swift
//  MusigDemo
//
//  Created by daiwei on 2021/9/24.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        let private0 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2"
        let private1 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38"
        let private2 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59"
        let pubkey0 = String.init(cString:get_my_pubkey(private0))
        let pubkey1 = String.init(cString:get_my_pubkey(private1))
        let pubkey2 = String.init(cString:get_my_pubkey(private2))
        var musig_0 = get_musig(private0)
        var musig_1 = get_musig(private1)
        var musig_2 = get_musig(private2)
        let commit_0 = String.init(cString:get_my_commit(musig_0))
        let commit_1 = String.init(cString:get_my_commit(musig_1))
        let commit_2 = String.init(cString:get_my_commit(musig_2))
        let commits = commit_0 + commit_1 + commit_2
        let pubkeys = pubkey0 + pubkey1 + pubkey2
        musig_0 = reveal_stage(musig_0, commits, pubkeys)
        musig_1 = reveal_stage(musig_1, commits, pubkeys)
        musig_2 = reveal_stage(musig_2, commits, pubkeys)
        let reveal_0 = String.init(cString:get_my_reveal(musig_0))
        let reveal_1 = String.init(cString:get_my_reveal(musig_1))
        let reveal_2 = String.init(cString:get_my_reveal(musig_2))
        let reveals = reveal_0 + reveal_1 + reveal_2
        musig_0 = cosign_stage(musig_0, reveals, pubkeys)
        musig_1 = cosign_stage(musig_1, reveals, pubkeys)
        musig_2 = cosign_stage(musig_2, reveals, pubkeys)
        let cosign_0 = String.init(cString:get_my_cosign(musig_0))
        let cosign_1 = String.init(cString:get_my_cosign(musig_1))
        let cosign_2 = String.init(cString:get_my_cosign(musig_2))
        let cosigns = cosign_0 + cosign_1 + cosign_2
        let signature = String.init(cString:get_signature(reveals, pubkeys, cosigns))
        let pubkey = String.init(cString:get_agg_pubkey(pubkeys))
        print("signature:", signature)
        print("pubkey:", pubkey)
    }


}

