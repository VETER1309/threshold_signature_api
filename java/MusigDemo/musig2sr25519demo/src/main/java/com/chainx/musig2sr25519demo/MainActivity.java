package com.chainx.musig2sr25519demo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.chainx.musig2_sr25519.Mast;
import com.chainx.musig2_sr25519.Musig2;

public class MainActivity extends AppCompatActivity {
    final static String phrase1 = "flame flock chunk trim modify raise rough client coin busy income smile";
    final static String phrase2 = "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics";
    final static String phrase3 = "awesome beef hill broccoli strike poem rebel unique turn circle cool system";

    final static long msg = 666666;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        String privateA = Musig2.getMyPrivkey(phrase1);
        String privateB = Musig2.getMyPrivkey(phrase2);
        String privateC = Musig2.getMyPrivkey(phrase3);

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
        String thresholdPubkey = Mast.generateThresholdPubkey(pubkeys, (byte) 2);
        String control = Mast.generateControlBlock(pubkeys, (byte) 2, pubkeyAB);

        System.out.println("thresholdPubkey:" + thresholdPubkey);
        System.out.println("control:" + control);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}