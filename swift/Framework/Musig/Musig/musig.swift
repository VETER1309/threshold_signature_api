//
//  musig.swift
//  MusigDemo
//
//  Created by daiwei on 2021/9/26.
//

import Foundation

public class Musig{
    let privkey: String
    let pubkey: String
    var musig: OpaquePointer?
    public init(priv: String){
        privkey = priv
        pubkey = String.init(cString:get_my_pubkey(priv))
        musig = get_musig(priv)
    }
    public func getMyCommit() -> String{
        return String.init(cString:get_my_commit(musig))
    }
    public func getMyPubkey() -> String{
        return pubkey
    }
    public func getMyReveal(commits:[String], pubkeys:[String]) -> String{
        if commits.count != pubkeys.count{
            return "Error"
        }
        musig = reveal_stage(musig, commits.joined(separator: ""), pubkeys.joined(separator: ""))
        return String.init(cString:get_my_reveal(musig))
    }
    public func getMyCosign(reveals:[String], pubkeys:[String]) -> String{
        if reveals.count != pubkeys.count{
            return "Error"
        }
        musig = cosign_stage(musig, reveals.joined(separator: ""), pubkeys.joined(separator: ""))
        return String.init(cString:get_my_cosign(musig))
    }
    public func getAggSignature(reveals:[String], cosigns:[String], pubkeys:[String]) -> String{
        if reveals.count != pubkeys.count || reveals.count != cosigns.count{
            return "Error"
        }
        return String.init(cString:get_signature(reveals.joined(separator: ""), pubkeys.joined(separator: ""), cosigns.joined(separator: "")))
    }
    public func getAggPublicKey(pubkeys:[String]) -> String{
        return String.init(cString:get_agg_pubkey(pubkeys.joined(separator: "")))
    }
}
