class Musig2 {
    public static native String get_my_privkey(String jarg1);
    public static native String get_my_pubkey(String jarg1);
    public static native long get_round1_state();
    public static native String encode_round1_state(long jarg1);
    public static native long decode_round1_state(String jarg1);
    public static native String get_round1_msg(long jarg1);
    public static native String get_round2_msg(long jarg1, String jarg2, String jarg3, String jarg4, String jarg5);
    public static native String get_signature(String jarg1);
    public static native String get_key_agg(String jarg1);
    public static native String generate_threshold_pubkey(String jarg1, long jarg2);
    public static native String generate_control_block(String jarg1, long jarg2, String jarg3);

    final static String phrase1 = "flame flock chunk trim modify raise rough client coin busy income smile";
    final static String phrase2 = "shrug argue supply evolve alarm caught swamp tissue hollow apology youth ethics";
    final static String phrase3 = "awesome beef hill broccoli strike poem rebel unique turn circle cool system";

    final static String msg = "b9b74d5852010cc4bf1010500ae6a97eca7868c9779d50c60fb4ae568b01ea38";

    static {
        System.loadLibrary("musig2_sr25519_dll");
    }

    public static String join(String sep, String[] reveals) {
        String result = reveals[0];
        for(int i = 1; i < reveals.length; i++) {
            result = result + sep + reveals[i];
        }
        return result;
    };
    public static String getMyPrivkey(String phrase) {
        return Musig2.get_my_privkey(phrase);
    }

    public static String getMyPubkey(String priv) {
        return Musig2.get_my_pubkey(priv);
    };

    public static String getAggPublicKey(String[] pubkeys) {
        return Musig2.get_key_agg(Musig2.join("", pubkeys));
    };

    public static long getRound1State() {
        return Musig2.get_round1_state();
    };

    public static String encodeRound1State(long round1State) {
        return Musig2.encode_round1_state(round1State);
    };

    public static long decodeRound1State(String round1State) {
        return Musig2.decode_round1_state(round1State);
    };

    public static String getRound1Msg(long round1State) {
        return Musig2.get_round1_msg(round1State);
    };

    public static String getRound2Msg(long round1State, String msg, String privkey, String[] pubkeys, String[] receivedRound1Msg){
        return Musig2.get_round2_msg(round1State, msg, privkey, Musig2.join("", pubkeys), Musig2.join("", receivedRound1Msg));
    };

    public static String getAggSignature(String[] receivedRound2Msg) {
        return Musig2.get_signature(Musig2.join("", receivedRound2Msg));
    };

    public static String generateThresholdPubkey(String[] pubkeys, byte threshold) {
        return Musig2.generate_threshold_pubkey(Musig2.join("", pubkeys), threshold);
    }

    public static String generateControlBlock(String[] pubkeys, byte threshold, String sigAggPubkey) {
        return Musig2.generate_control_block(Musig2.join("", pubkeys), threshold, sigAggPubkey);
    }

    public static void main(String[] args) {

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
        String thresholdPubkey = Musig2.generateThresholdPubkey(pubkeys, (byte) 2);
        String control = Musig2.generateControlBlock(pubkeys, (byte) 2, pubkeyAB);

        System.out.println("thresholdPubkey:" + thresholdPubkey);
        System.out.println("control:" + control);
    }
}
