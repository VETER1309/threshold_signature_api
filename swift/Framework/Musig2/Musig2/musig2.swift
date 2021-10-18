//
//  musig2.swift
//  Musig2
//
//  Created by daiwei on 2021/10/16.
//

import Foundation

public func getRound1State(priv: String) -> OpaquePointer?{
    return get_round1_state(priv)
}

public func getMyPubkey(priv: String) -> String{
    return String.init(cString:get_my_pubkey(priv))
}

public func getRound1Msg(state:OpaquePointer?) -> String{
    return String.init(cString:get_round1_msg(state))
}

public func encodeRound1State(state:OpaquePointer?) -> String{
    return String.init(cString:encode_round1_state(state))
}

public func decodeRound1State(round1_state:String) -> OpaquePointer?{
    return decode_round1_state(round1_state)
}

public func getRound2Msg(state:OpaquePointer?, msg:String, my_pubkey:String, pubkeys:[String], received_round1_msg:[String]) -> String{
    return String.init(cString:get_round2_msg(state, msg, my_pubkey, pubkeys.joined(separator: ""), received_round1_msg.joined(separator: "")))
}

public func getAggSignature(round2_msg:[String]) -> String{
    return String.init(cString:get_signature(round2_msg.joined(separator: "")))
}
public func getAggPublicKey(pubkeys:[String]) -> String{
    return String.init(cString:get_key_agg(pubkeys.joined(separator: "")))
}

public func generateThresholdPubkey(pubkeys:[String], threshold: UInt8) -> String {
    return String.init(cString:generate_threshold_pubkey(pubkeys.joined(separator: ""), threshold))
}

public func generateControlBlock(pubkeys:[String], threshold: UInt8, agg_pubkey: String) -> String {
    return String.init(cString:generate_control_block(pubkeys.joined(separator: ""), threshold, agg_pubkey))
}