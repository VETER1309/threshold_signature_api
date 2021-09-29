package com.example.musigdemo;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import com.example.musig.Musig;

public class MainActivity extends AppCompatActivity {
    final static String private1 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2";
    final static String private2 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38";
    final static String private3 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Musig musig0 = new Musig(private1);
        Musig musig1 = new Musig(private2);
        Musig musig2 = new Musig(private3);

        String commit0 = musig0.getMyCommit();
        String commit1 = musig1.getMyCommit();
        String commit2 = musig2.getMyCommit();
        
        String pubkey0 = musig0.getMyPubkey();
        String pubkey1 = musig1.getMyPubkey();
        String pubkey2 = musig2.getMyPubkey();

        String reveal0 = musig0.getMyReveal(new String[]{commit1, commit2},
                new String[]{pubkey1, pubkey2});
        String reveal1 = musig1.getMyReveal(new String[]{commit0, commit2},
                new String[]{pubkey0, pubkey2});
        String reveal2 = musig2.getMyReveal(new String[]{commit0, commit1},
                new String[]{pubkey0, pubkey1});

        String cosign0 = musig0.getMyCosign(new String[]{reveal1, reveal2},
                new String[]{pubkey1, pubkey2});
        String cosign1 = musig1.getMyCosign(new String[]{reveal0, reveal2},
                new String[]{pubkey0, pubkey2});
        String cosign2 = musig2.getMyCosign(new String[]{reveal0, reveal1},
                new String[]{pubkey0, pubkey1});

        String signature = musig0.getAggSignature(new String[]{reveal0, reveal1, reveal2},
                new String[]{cosign0, cosign1, cosign2},
                new String[]{pubkey0, pubkey1, pubkey2});

        String pubkey = musig0.getAggPublicKey(new String[]{pubkey0, pubkey1, pubkey2});

        System.out.println("signature:" + signature);
        System.out.println("pubkey:" + pubkey);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}