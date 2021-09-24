package com.example;

/**
 * Hello world!
 *
 */
public class App {

    final static String private1 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2";
    final static String private2 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38";
    final static String private3 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59";

    public static void main(String[] args) {
        Musig musig1 = new Musig(private1);
        Musig musig2 = new Musig(private2);
        Musig musig3 = new Musig(private3);

        String commit1 = musig1.GetMyCommit();
        String commit2 = musig2.GetMyCommit();
        String commit3 = musig3.GetMyCommit();

        String reveal1 = musig1.GetMyReveal(new String[] { commit2, commit3 },
                new String[] { musig2.pubkey, musig3.pubkey });
        String reveal2 = musig2.GetMyReveal(new String[] { commit1, commit3 },
                new String[] { musig1.pubkey, musig3.pubkey });
        String reveal3 = musig3.GetMyReveal(new String[] { commit1, commit2 },
                new String[] { musig1.pubkey, musig2.pubkey });

        String cosign1 = musig1.GetMyCosign(new String[] { reveal2, reveal3 },
                new String[] { musig2.pubkey, musig3.pubkey });
        String cosign2 = musig2.GetMyCosign(new String[] { reveal1, reveal3 },
                new String[] { musig1.pubkey, musig3.pubkey });
        String cosign3 = musig3.GetMyCosign(new String[] { reveal1, reveal2 },
                new String[] { musig1.pubkey, musig2.pubkey });

        String signature = musig1.GetAggSignature(new String[] { reveal1, reveal2, reveal3 },
                new String[] { cosign1, cosign2, cosign3 },
                new String[] { musig1.pubkey, musig2.pubkey, musig3.pubkey });

        String aggPubkey = musig1.GetAggPublicKey(new String[] { musig1.pubkey, musig2.pubkey, musig3.pubkey });

        System.out.println(signature);
        System.out.println(aggPubkey);
    }
}