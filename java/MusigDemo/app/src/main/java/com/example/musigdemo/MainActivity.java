package com.example.musigdemo;

import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.chainx.musig.Musig;
import com.chainx.musig.Mast;

public class MainActivity extends AppCompatActivity {
    final static String private1 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2";
    final static String private2 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38";
    final static String private3 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59";

    final static String publicA = "005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d";
    final static String publicB = "90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547";
    final static String publicC = "66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415";
    final static String publicAB = "7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Musig musig0 = new Musig(private1);
        Musig musig1 = new Musig(private2);
        Musig musig2 = new Musig(private3);

        String pubkey0 = musig0.getMyPubkey();
        String pubkey1 = musig1.getMyPubkey();
        String pubkey2 = musig2.getMyPubkey();

        String reveal0 = musig0.getMyReveal();
        String reveal1 = musig1.getMyReveal();
        String reveal2 = musig2.getMyReveal();

        String cosign0 = musig0.getMyCosign(new String[]{reveal1, reveal2},
                new String[]{pubkey1, pubkey2});
        String cosign1 = musig1.getMyCosign(new String[]{reveal0, reveal2},
                new String[]{pubkey0, pubkey2});
        String cosign2 = musig2.getMyCosign(new String[]{reveal0, reveal1},
                new String[]{pubkey0, pubkey1});

        String signature = Musig.getAggSignature(new String[]{reveal0, reveal1, reveal2},
                new String[]{cosign0, cosign1, cosign2},
                new String[]{pubkey0, pubkey1, pubkey2});

        String pubkey = Musig.getAggPublicKey(new String[]{pubkey0, pubkey1, pubkey2});

        System.out.println("signature:" + signature);
        System.out.println("pubkey:" + pubkey);

        Mast mast = new Mast(new String[]{publicA, publicB, publicC}, (byte) 2);
        String thresholdPubkey = mast.generateThresholdPubkey();
        String control = mast.generateControlBlock(publicAB);

        System.out.println("thresholdPubkey:" + thresholdPubkey);
        System.out.println("control:" + control);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}