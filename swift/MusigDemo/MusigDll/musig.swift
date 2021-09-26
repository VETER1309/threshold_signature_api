//
//  musig.swift
//  MusigDemo
//
//  Created by daiwei on 2021/9/26.
//

import Foundation

class Musig{
    let privkey: String
    let pubkey: String
    var musig: OpaquePointer?
    var commit: String
    var reveal: String
    var cosign: String
    init(priv: String){
        privkey = priv
        pubkey = String.init(cString:get_my_pubkey(priv))
        musig = get_musig(priv)
        commit = ""
        reveal = ""
        cosign = ""
    }
    func getMyCommit() -> String{
        commit = String.init(cString:get_my_commit(musig))
        return commit
    }
    func getMyPubkey() -> String{
        return pubkey
    }
    func getMyReveal(commits:[String], pubkeys:[String]) -> String{
        if commits.count != pubkeys.count{
            return "Error"
        }
        var commits_str = commit;
        var pubkeys_str = pubkey;
        for i in 0..<commits.count{
            commits_str += commits[i]
            pubkeys_str += pubkeys[i]
        }
        musig = reveal_stage(musig, commits_str, pubkeys_str)
        reveal = String.init(cString:get_my_reveal(musig))
        return reveal
    }
    func getMyCosign(reveals:[String], pubkeys:[String]) -> String{
        if reveals.count != pubkeys.count{
            return "Error"
        }
        var reveals_str = reveal;
        var pubkeys_str = pubkey;
        for i in 0..<reveals.count{
            reveals_str += reveals[i]
            pubkeys_str += pubkeys[i]
        }
        musig = cosign_stage(musig, reveals_str, pubkeys_str)
        cosign = String.init(cString:get_my_cosign(musig))
        return cosign
    }
    func getAggSignature(reveals:[String], cosigns:[String], pubkeys:[String]) -> String{
        if reveals.count != pubkeys.count || reveals.count != cosigns.count{
            return "Error"
        }
        var reveals_str = "";
        var cosigns_str = "";
        var pubkeys_str = "";
        for i in 0..<reveals.count{
            reveals_str += reveals[i]
            cosigns_str += cosigns[i]
            pubkeys_str += pubkeys[i]
        }
        return String.init(cString:get_signature(reveals_str, pubkeys_str, cosigns_str))
    }
    func getAggPublicKey(pubkeys:[String]) -> String{
        var pubkeys_str = "";
        for i in 0..<pubkeys.count{
            pubkeys_str += pubkeys[i]
        }
        return String.init(cString:get_agg_pubkey(pubkeys_str))
    }
}
