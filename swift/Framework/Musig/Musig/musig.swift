//
//  musig.swift
//  MusigDemo
//
//  Created by daiwei on 2021/9/26.
//

import Foundation

public func getMusig(priv: String) -> OpaquePointer?{
    return get_musig(priv)
}

public func getMyPrivkey(phrase: String) -> String{
    return String.init(cString:get_my_privkey(phrase))
}

public func getMyPubkey(priv: String) -> String{
    return String.init(cString:get_my_pubkey(priv))
}

public func getMyReveal(musig:OpaquePointer?) -> String{
    return String.init(cString:get_my_reveal(musig))
}

public func encodeRevealStage(musig:OpaquePointer?) -> String{
    return String.init(cString:encode_reveal_stage(musig))
}

public func decodeRevealStage(reveal_stage:String) -> OpaquePointer?{
    return decode_reveal_stage(reveal_stage)
}

public func getMyCosign(musig:OpaquePointer?, reveals:[String], pubkeys:[String]) -> String{
    let musig = cosign_stage(musig, reveals.joined(separator: ""), pubkeys.joined(separator: ""))
    return String.init(cString:get_my_cosign(musig))
}

public func getAggSignature(reveals:[String], cosigns:[String], pubkeys:[String]) -> String{
    return String.init(cString:get_signature(reveals.joined(separator: ""), pubkeys.joined(separator: ""), cosigns.joined(separator: "")))
}
public func getAggPublicKey(pubkeys:[String]) -> String{
    return String.init(cString:get_agg_pubkey(pubkeys.joined(separator: "")))
}

public func generateThresholdPubkey(pubkeys:[String], threshold: UInt8) -> String {
    return String.init(cString:generate_threshold_pubkey(pubkeys.joined(separator: ""), threshold))
}

public func generateControlBlock(pubkeys:[String], threshold: UInt8, agg_pubkey: String) -> String {
    return String.init(cString:generate_control_block(pubkeys.joined(separator: ""), threshold, agg_pubkey))
}
