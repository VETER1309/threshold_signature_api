package com.example.musigdemo;

import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.chainx.musig.Musig;
import com.chainx.musig.Mast;
import com.sun.jna.Pointer;

public class MainActivity extends AppCompatActivity {
    final static String phrase1 = "flame flock chunk trim modify raise rough client coin busy income smile"
    final static String phrase2 = "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics"
    final static String phrase3 = "awesome beef hill broccoli strike poem rebel unique turn circle cool system"

    final static String publicA = "005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d";
    final static String publicB = "90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547";
    final static String publicC = "66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415";
    final static String publicAB = "7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        String private1 = Musig.getMyPrivkey(phrase1);
        String private2 = Musig.getMyPrivkey(phrase2);
        String private3 = Musig.getMyPrivkey(phrase3);

        Pointer musig0 = Musig.getMusig(private1);
        String encodeMusig0 = Musig.encodeRevealStage(musig0);
        musig0 = Musig.decodeRevealStage(encodeMusig0);

        Pointer musig1 = Musig.getMusig(private2);
        Pointer musig2 = Musig.getMusig(private3);

        String pubkey0 = Musig.getMyPubkey(private1);
        String pubkey1 = Musig.getMyPubkey(private2);
        String pubkey2 = Musig.getMyPubkey(private3);

        String reveal0 = Musig.getMyReveal(musig0);
        String reveal1 = Musig.getMyReveal(musig1);
        String reveal2 = Musig.getMyReveal(musig2);

        String cosign0 = Musig.getMyCosign(musig0, new String[]{reveal1, reveal2},
                new String[]{pubkey1, pubkey2});
        String cosign1 = Musig.getMyCosign(musig1, new String[]{reveal0, reveal2},
                new String[]{pubkey0, pubkey2});
        String cosign2 = Musig.getMyCosign(musig2, new String[]{reveal0, reveal1},
                new String[]{pubkey0, pubkey1});

        String signature = Musig.getAggSignature(new String[]{reveal0, reveal1, reveal2},
                new String[]{cosign0, cosign1, cosign2},
                new String[]{pubkey0, pubkey1, pubkey2});

        String pubkey = Musig.getAggPublicKey(new String[]{pubkey0, pubkey1, pubkey2});

        System.out.println("signature:" + signature);
        System.out.println("pubkey:" + pubkey);

        String thresholdPubkey = Mast.generateThresholdPubkey(new String[]{publicA, publicB, publicC}, (byte) 2);
        String control = Mast.generateControlBlock(new String[]{publicA, publicB, publicC}, (byte) 2, publicAB);

        System.out.println("thresholdPubkey:" + thresholdPubkey);
        System.out.println("control:" + control);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}