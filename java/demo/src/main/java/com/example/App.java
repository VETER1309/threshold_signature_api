package com.example;

import com.sun.jna.*;

/**
 * Hello world!
 *
 */
public class App {

    public interface CLibrary extends Library {
        public String get_my_pubkey(String priv);

        public Pointer get_musig(String priv);

        public String get_my_commit(Pointer musig);

        public Pointer reveal_stage(Pointer musig, String commits, String pubkeys);

        public String get_my_reveal(Pointer musig);

        public Pointer cosign_stage(Pointer musig, String reveals, String pubkeys);

        public String get_my_cosign(Pointer musig);

        public String get_signature(String reveals, String pubkeys, String cosigns);

        public String get_agg_pubkey(String pubkeys);
    }

    public static void main(String[] args) {
        final CLibrary clib = (CLibrary) Native.load(
                "/home/hacpy/Work/Dev/chainx-org/threshold_signature_api/musig-dll/target/release/libmusig_dll.so",
                CLibrary.class);

        String private1 = "54fa29a5b57041e930b2b0b7939540c076cda3754c4dc2ddb184fe60fe1b7f0c76df013ca315ae0a51a2b9a3eadfaca4fc91a750667d8d8592b0154e381c6da2";
        String private2 = "db43ffe916f7aacef99a136ec04a504ab1b95a4023e1c2d2b36e98649bfcff0f45ceb6016fb7292732b940c1efe74d4fc20959a05869b79823ce01f06da84d38";
        String private3 = "330d9f80e441be557a899b6cda38f243f1c089c8dd985df86f74a8f92f6025076ce7f9ba2ab95e2d33a24c16e4fd27c9bb73374045e23598f81cc670b57b4b59";

        String pubkey1 = clib.get_my_pubkey(private1);
        String pubkey2 = clib.get_my_pubkey(private2);
        String pubkey3 = clib.get_my_pubkey(private3);

        Pointer musig1 = clib.get_musig(private1);
        Pointer musig2 = clib.get_musig(private2);
        Pointer musig3 = clib.get_musig(private3);

        String commit1 = clib.get_my_commit(musig1);
        String commit2 = clib.get_my_commit(musig2);
        String commit3 = clib.get_my_commit(musig3);

        Pointer musig1_reveal = clib.reveal_stage(musig1, commit2.concat(commit3),pubkey2.concat(pubkey3));
        Pointer musig2_reveal = clib.reveal_stage(musig2, commit1.concat(commit3), pubkey1.concat(pubkey3));
        Pointer musig3_reveal = clib.reveal_stage(musig3, commit1.concat(commit2), pubkey1.concat(pubkey2));

        String reveal1 = clib.get_my_reveal(musig1_reveal);
        String reveal2 = clib.get_my_reveal(musig2_reveal);
        String reveal3 = clib.get_my_reveal(musig3_reveal);

        Pointer musig1_cosign = clib.cosign_stage(musig1, reveal2.concat(reveal3), pubkey2.concat(pubkey3));
        Pointer musig2_cosign = clib.cosign_stage(musig2, reveal1.concat(reveal3), pubkey1.concat(pubkey3));
        Pointer musig3_cosign = clib.cosign_stage(musig3, reveal1.concat(reveal2), pubkey1.concat(pubkey2));

        String cosign1 = clib.get_my_cosign(musig1_cosign);
        String cosign2 = clib.get_my_cosign(musig2_cosign);
        String cosign3 = clib.get_my_cosign(musig3_cosign);

        String signature = clib.get_signature(reveal1.concat(reveal2).concat(reveal3), pubkey1.concat(pubkey2).concat(pubkey3), cosign1.concat(cosign2).concat(cosign3));
        String aggPubkey = clib.get_agg_pubkey(pubkey1.concat(pubkey2).concat(pubkey3));

        System.out.println(signature);
        System.out.println(aggPubkey);
    }
}