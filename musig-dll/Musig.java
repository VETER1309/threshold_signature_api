class Musig {
    public static native String get_my_pubkey(String priv);
    public static native String get_my_privkey(String phrase);
    public static native long get_musig(String priv);
    public static native String get_my_reveal(long musig);
    public static native long cosign_stage(long musig, String reveals, String pubkeys);
    public static native String get_my_cosign(long musig);
    public static native String get_signature(String reveals, String pubkeys, String cosigns);
    public static native String get_agg_pubkey(String pubkeys);
    public static native String encode_reveal_stage(long musig);
    public static native long decode_reveal_stage(String musig);
    public static native String encode_cosign_stage(long musig);
    public static native long decode_cosign_stage(String musig);
    public static native String generate_threshold_pubkey(String jarg1, long jarg2);
    public static native String generate_control_block(String jarg1, long jarg2, String jarg3);

    final static String phrase1 = "flame flock chunk trim modify raise rough client coin busy income smile";
    final static String phrase2 = "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics";
    final static String phrase3 = "awesome beef hill broccoli strike poem rebel unique turn circle cool system";

    final static String publicA = "005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d";
    final static String publicB = "90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547";
    final static String publicC = "66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415";
    final static String publicAB = "7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861";

    static {
        System.loadLibrary("musig_dll");
    }

    public static String join(String sep, String[] reveals) {
        String result = reveals[0];
        for(int i = 1; i < reveals.length; i++) {
            result = result + sep + reveals[i];
        }
        return result;
    };
    public static long getMusig(String priv) {
        return get_musig(priv);
    }

    public static String getMyPubkey(String priv) {
        return get_my_pubkey(priv);
    }

    public static String getMyPrivkey(String phrase) {
        return get_my_privkey(phrase);
    }

    public static String getMyReveal(long musig) {
        return get_my_reveal(musig);
    }

    public static String getMyCosign(long musig, String[] reveals, String[] pubkeys) {
        musig = cosign_stage(musig, join("", reveals), join("", pubkeys));
        return get_my_cosign(musig);
    }

    public static String encodeRevealStage(long musig) {
        return encode_reveal_stage(musig);
    }

    public static long decodeRevealStage(String musig) {
        return decode_reveal_stage(musig);
    }

    public static String encodeCosignStage(long musig) {
        return encode_cosign_stage(musig);
    }

    public static long decodeCosignStage(String musig) {
        return decode_cosign_stage(musig);
    }

    public static String getAggSignature(String[] reveals, String[] cosigns, String[] pubkeys) {
        return get_signature(join("", reveals), join("", pubkeys), join("", cosigns));
    }

    public static String getAggPublicKey(String[] pubkeys) {
        return get_agg_pubkey(join("", pubkeys));
    }

    public static String generateThresholdPubkey(String[] pubkeys, byte threshold) {
        return generate_threshold_pubkey(join("", pubkeys), threshold);
    }

    public static String generateControlBlock(String[] pubkeys, byte threshold, String sigAggPubkey) {
        return generate_control_block(join("", pubkeys), threshold, sigAggPubkey);
    }

    public static void main(String[] args) {

        String private1 = Musig.getMyPrivkey(phrase1);
        String private2 = Musig.getMyPrivkey(phrase2);
        String private3 = Musig.getMyPrivkey(phrase3);

        long musig0 = Musig.getMusig(private1);
        String encodeMusig0 = Musig.encodeRevealStage(musig0);
        musig0 = Musig.decodeRevealStage(encodeMusig0);

        long musig1 = Musig.getMusig(private2);
        long musig2 = Musig.getMusig(private3);

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

        String thresholdPubkey = Musig.generateThresholdPubkey(new String[]{publicA, publicB, publicC}, (byte) 2);
        String control = Musig.generateControlBlock(new String[]{publicA, publicB, publicC}, (byte) 2, publicAB);

        System.out.println("thresholdPubkey:" + thresholdPubkey);
        System.out.println("control:" + control);
    }
}
