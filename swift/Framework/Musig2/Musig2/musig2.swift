//
//  musig2.swift
//  Musig2
//
//  Created by daiwei on 2021/10/16.
//

import Foundation

public func getRound1State() -> OpaquePointer?{
    return get_round1_state()
}

public func getMyPrivkey(phrase: String, pd_passphrase: String) -> String{
    return String.init(cString:get_my_privkey(phrase, pd_passphrase))
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

public func getRound2Msg(state:OpaquePointer?, msg:String, priv:String, pubkeys:[String], received_round1_msg:[String]) -> String{
    return String.init(cString:get_round2_msg(state, msg, priv, pubkeys.joined(separator: ""), received_round1_msg.joined(separator: "")))
}

public func getAggSignature(round2_msg:[String]) -> String{
    return String.init(cString:get_signature(round2_msg.joined(separator: "")))
}
public func getAggPublicKey(pubkeys:[String]) -> String{
    return String.init(cString:get_key_agg(pubkeys.joined(separator: "")))
}

public func generateThresholdPubkey(pubkeys:[String], threshold: UInt8, network: String) -> String {
    return String.init(cString:generate_threshold_pubkey(pubkeys.joined(separator: ""), threshold, network))
}

public func generateControlBlock(pubkeys:[String], threshold: UInt8, agg_pubkey: String) -> String {
    return String.init(cString:generate_control_block(pubkeys.joined(separator: ""), threshold, agg_pubkey))
}

public func generateSchnorrSignature(message: String, privkey: String) -> String {
    return String.init(cString:generate_schnorr_signature(message, privkey))
}

public func getScriptPubkey(addr: String) -> String {
    return String.init(cString:get_scirpt_pubkey(addr))
}

public func generateRawTx(txids: [String], indexs: [UInt32], addresses: [String],  amounts: [UInt64]) -> String{
    if txids.count != indexs.count{
        return "txids and indexs must be equal in length";
    }
    if addresses.count != amounts.count{
        return "addresses and amounts must be equal in length";
    }
    if txids.count == 0{
        return "Input count must be greater than 0";
    }
    if addresses.count == 0{
        return "Output count must be greater than 0";
    }

    var base_tx = String.init(cString:get_base_tx(txids[0], indexs[0]));
    for i in 1..<txids.count {
        base_tx = String.init(cString:add_input(base_tx, txids[i], indexs[i]));
    }
    for i in 0..<addresses.count{
        base_tx = String.init(cString:add_output(base_tx, addresses[i], amounts[i]));
    }
    return base_tx;
}

public func getSighash(prev_tx: String, tx: String, input_index: UInt32, agg_pubkey: String, sigversion: UInt32) -> String{
    return String.init(cString:get_sighash(prev_tx, tx, input_index, agg_pubkey, sigversion));
}

public func buildThresholdTx(tx: String, agg_signature: String, agg_pubkey: String, control: String, input_index: UInt32) -> String{
    return String.init(cString:build_raw_scirpt_tx(tx, agg_signature, agg_pubkey, control, input_index));
}

public func buildTaprootTx(tx: String, signature: String, input_index: UInt32) -> String{
    return String.init(cString:build_raw_key_tx(tx, signature, input_index));
}
