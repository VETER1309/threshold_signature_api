package com.chainx.musig2demo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.chainx.musig2.Mast;
import com.chainx.musig2.Musig2;
import com.chainx.musig2.Transaction;

public class MainActivity extends AppCompatActivity {

    final static String privateA = "5495822c4f8efbe17b9bae42a85e8998baec458f3824440d1ce8d9357ad4a7b7";
    final static String privateB = "cef4bbc9689812098c379bec0bb063a895916008344ca04cddbd21ccbcce3bcf";
    final static String privateC = "c9045032eb6df7ebc51d862f9a6a8ffa90eb691dc1b70b4c7b8d1ed0fd8cc25f";

    final static String msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38";

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        String pubkeyA = Musig2.getMyPubkey(privateA);
        String pubkeyB = Musig2.getMyPubkey(privateB);
        String pubkeyC = Musig2.getMyPubkey(privateC);

        long round1StateA = Musig2.getRound1State();
        long round1StateB = Musig2.getRound1State();
        long round1StateC = Musig2.getRound1State();

        String encodedRound1StateA = Musig2.encodeRound1State(round1StateA);
        round1StateA = Musig2.decodeRound1State(encodedRound1StateA);

        String round1MsgA = Musig2.getRound1Msg(round1StateA);
        String round1MsgB = Musig2.getRound1Msg(round1StateB);
        String round1MsgC = Musig2.getRound1Msg(round1StateC);

        String[] pubkeys = new String[]{pubkeyA, pubkeyB, pubkeyC};

        String round2MsgA = Musig2.getRound2Msg(round1StateA, msg, privateA, pubkeys, new String[]{round1MsgB, round1MsgC});
        String round2MsgB = Musig2.getRound2Msg(round1StateB, msg, privateB, pubkeys, new String[]{round1MsgA, round1MsgC});
        String round2MsgC = Musig2.getRound2Msg(round1StateC, msg, privateC, pubkeys, new String[]{round1MsgA, round1MsgB});

        String sig = Musig2.getAggSignature(new String[]{round2MsgA, round2MsgB, round2MsgC});
        String pubkey = Musig2.getAggPublicKey(pubkeys);
        System.out.println("signature: " + sig);
        System.out.println("pubkey: " + pubkey);

        String pubkeyAB = Musig2.getAggPublicKey(new String[]{pubkeyA, pubkeyB});
        String thresholdPubkey = Mast.generateThresholdPubkey(pubkeys, (byte) 2, "mainnet");
        String control = Mast.generateControlBlock(pubkeys, (byte) 2, pubkeyAB);

        System.out.println("thresholdPubkey:" + thresholdPubkey);
        System.out.println("control:" + control);

        // Generate taproot tx
        String private_char = "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40";
        String prev_tx = "020000000001014be640313b023c3c731b7e89c3f97bebcebf9772ea2f7747e5604f4483a447b601000000000000000002a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bbc027090000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01404dc68b31efc1468f84db7e9716a84c19bbc53c2d252fd1d72fa6469e860a74486b0990332b69718dbcb5acad9d48634d23ee9c215ab15fb16f4732bed1770fdf00000000";
        String[] txids = new String[]{"1f8e0f7dfa37b184244d022cdf2bc7b8e0bac8b52143ea786fa3f7bbe049eeae"};
        long[] indexs = new long[]{1};
        String[] addresses = new String[]{"tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw", "35516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38", "tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68"};
        long[] amounts = new long[]{100000, 0, 400000};

        String tx = Transaction.generateRawTx(txids, indexs, addresses, amounts);
        String sighash = Transaction.getSighash(prev_tx, tx, 0, "", 0);
        System.out.println("sighash: " + sighash);
        String schnorr_signature = Transaction.generateSchnorrSignature(sighash, private_char);
        System.out.println("schnorr_signature: " + schnorr_signature);
        String taproot_tx = Transaction.buildTaprootTx(tx, schnorr_signature, 0);
        System.out.println("taproot_tx: " + taproot_tx);

        // Generate Threshold tx
        String private_a = "e5bb018d70c6fb5dd8ad91f6c88fb0e6fdab2c482978c95bb3794ca6e2e50dc2";
        String private_b = "a7150e8f24ab26ebebddd831aeb8f00ecb593df3b80ae1e8b8be01351805f2d6";
        String private_c = "4a84a4601e463bc02dd0b8be03f3721187e9fc3105d5d5e8930ff3c8ca15cf40";
        String prev_tx_1 = "02000000000101aeee49e0bbf7a36f78ea4321b5c8bae0b8c72bdf2c024d2484b137fa7d0f8e1f01000000000000000003a0860100000000002251209a9ea267884f5549c206b2aec2bd56d98730f90532ea7f7154d4d4f923b7e3bb0000000000000000326a3035516a706f3772516e7751657479736167477a6334526a376f737758534c6d4d7141754332416255364c464646476a38801a060000000000225120c9929543dfa1e0bb84891acd47bfa6546b05e26b7a04af8eb6765fcc969d565f01409e325889515ed47099fdd7098e6fafdc880b21456d3f368457de923f4229286e34cef68816348a0581ae5885ede248a35ac4b09da61a7b9b90f34c200872d2e300000000";
        String pubkey_a = Musig2.getMyPubkey(private_a);
        String pubkey_b = Musig2.getMyPubkey(private_b);
        String pubkey_c = Musig2.getMyPubkey(private_c);
        String pubkey_bc = Musig2.getAggPublicKey(new String[]{pubkey_b, pubkey_c});
        String[] txids_1 = new String[]{"8e5d37c768acc4f3e794a10ad27bf0256237c80c22fa67117e3e3e1aec22ea5f"};
        long[] indexs_1 = new long[]{0};
        String[] addresses_1 = new String[]{"tb1pexff2s7l58sthpyfrtx500ax234stcnt0gz2lr4kwe0ue95a2e0srxsc68", "tb1pn202yeugfa25nssxk2hv902kmxrnp7g9xt487u256n20jgahuwasdcjfdw"};
        long[] amounts_1 = new long[]{50000, 40000};
        String tx_1 = Transaction.generateRawTx(txids_1, indexs_1, addresses_1, amounts_1);
        String sighash_1 = Transaction.getSighash(prev_tx_1, tx_1, 0, pubkey_bc, 1);
        System.out.println("sighash_1: " + sighash_1);
        // Here is the aggregate signature of sighash of two persons b and c
        String multi_signature = "2639d4d9882f6e7e42db38dbd2845c87b131737bf557643ef575c49f8fc6928869d9edf5fd61606fb07cced365fdc2c7b637e6ecc85b29906c16d314e7543e94";
        String control_1 = Mast.generateControlBlock(new String[]{pubkey_a, pubkey_b, pubkey_c}, (byte) 2, pubkey_bc);
        String threshold_tx = Transaction.buildThresholdTx(tx_1, multi_signature, pubkey_bc, control_1, 0);
        System.out.println("threshold_tx: " + threshold_tx);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}