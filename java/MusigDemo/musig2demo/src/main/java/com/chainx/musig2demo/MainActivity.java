package com.chainx.musig2demo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.chainx.musig2.Mast;
import com.chainx.musig2.Musig2;

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
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}