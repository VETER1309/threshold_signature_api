package com.chainx.musig2demo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.chainx.musig2.Musig2;
import com.sun.jna.Pointer;

public class MainActivity extends AppCompatActivity {

    final static String privateA = "5495822c4f8efbe17b9bae42a85e8998baec458f3824440d1ce8d9357ad4a7b7";
    final static String privateB = "cef4bbc9689812098c379bec0bb063a895916008344ca04cddbd21ccbcce3bcf";
    final static String privateC = "c9045032eb6df7ebc51d862f9a6a8ffa90eb691dc1b70b4c7b8d1ed0fd8cc25f";

    final static String msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Pointer keypairA = Musig2.getMyKeypair(privateA);
        Pointer keypairB = Musig2.getMyKeypair(privateA);
        Pointer keypairC = Musig2.getMyKeypair(privateA);

        String pubkeyA = Musig2.getMyPubkey(keypairA);
        String pubkeyB = Musig2.getMyPubkey(keypairB);
        String pubkeyC = Musig2.getMyPubkey(keypairC);

        String[] pubkeys = new String[]{pubkeyA, pubkeyB, pubkeyC};

        String aggPubkey = Musig2.getAggKey(pubkeys);

        Pointer round1StateA = Musig2.getRound1State(keypairA);
        Pointer round1StateB = Musig2.getRound1State(keypairB);
        Pointer round1StateC = Musig2.getRound1State(keypairC);

        String round1MsgA = Musig2.getRound1Msg(round1StateA);
        String round1MsgB = Musig2.getRound1Msg(round1StateB);
        String round1MsgC = Musig2.getRound1Msg(round1StateC);

        Pointer round2StateA = Musig2.getRound2State(round1StateA, msg, pubkeyA, pubkeys, new String[]{round1MsgB, round1MsgC});
        Pointer round2StateB = Musig2.getRound2State(round1StateB, msg, pubkeyB, pubkeys, new String[]{round1MsgA, round1MsgC});
        Pointer round2StateC = Musig2.getRound2State(round1StateC, msg, pubkeyC, pubkeys, new String[]{round1MsgA, round1MsgB});

        String round2RA = Musig2.getRound2R(round2StateA);
        String round2RB = Musig2.getRound2R(round2StateB);
        String round2RC = Musig2.getRound2R(round2StateC);

        String round2MsgA = Musig2.getRound2Msg(round2StateA);
        String round2MsgB = Musig2.getRound2Msg(round2StateB);
        String round2MsgC = Musig2.getRound2Msg(round2StateC);

        String sig = Musig2.getSignature(round2StateA, new String[]{round2MsgB, round2MsgC}, round2RA);

        System.out.println("A's signature:" + sig);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}