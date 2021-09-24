package com.example;

import com.sun.jna.*;

public class Musig {
    public String privkey;
    public String pubkey;
    public Pointer musig;

    public Musig(String priv) {
        privkey = priv;
        pubkey = clib.get_my_pubkey(priv);
        musig = clib.get_musig(priv);
    }

    public String GetMyCommit() {
        return clib.get_my_commit(musig);
    }

    public String GetMyReveal(String[] commits, String[] pubkeys) {
        if (commits.length != pubkeys.length) {
            return "Error";
        }
        
        musig = clib.reveal_stage(musig, 
                String.join("", commits), String.join("", pubkeys));
        return clib.get_my_reveal(musig);
    }

    public String GetMyCosign(String[] reveals, String[] pubkeys) {
        if (reveals.length != pubkeys.length) {
            return "Error";
        }
        musig = clib.cosign_stage(musig, String.join("", reveals), String.join("", pubkeys));
        return clib.get_my_cosign(musig);
    }

    public String GetAggSignature(String[] reveals, String[] cosigns, String[] pubkeys) {
        return clib.get_signature(String.join("", reveals), String.join("", pubkeys), String.join("", cosigns));
    }

    public String GetAggPublicKey(String[] pubkeys) {
        return clib.get_agg_pubkey(String.join("", pubkeys));
    }

    final CLibrary clib = (CLibrary) Native.load(
            "/home/hacpy/Work/Dev/chainx-org/threshold_signature_api/musig-dll/target/release/libmusig_dll.so",
            CLibrary.class);

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
}
