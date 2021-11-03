/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class Musig2 */

#ifndef _Included_Musig2
#define _Included_Musig2
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     Musig2
 * Method:    get_my_privkey
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_get_1my_1privkey
  (JNIEnv *, jclass, jstring);

/*
 * Class:     Musig2
 * Method:    get_my_pubkey
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_get_1my_1pubkey
  (JNIEnv *, jclass, jstring);

/*
 * Class:     Musig2
 * Method:    get_round1_state
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_Musig2_get_1round1_1state
  (JNIEnv *, jclass);

/*
 * Class:     Musig2
 * Method:    encode_round1_state
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_encode_1round1_1state
  (JNIEnv *, jclass, jlong);

/*
 * Class:     Musig2
 * Method:    decode_round1_state
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_Musig2_decode_1round1_1state
  (JNIEnv *, jclass, jstring);

/*
 * Class:     Musig2
 * Method:    get_round1_msg
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_get_1round1_1msg
  (JNIEnv *, jclass, jlong);

/*
 * Class:     Musig2
 * Method:    get_round2_msg
 * Signature: (JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_get_1round2_1msg
  (JNIEnv *, jclass, jlong, jstring, jstring, jstring, jstring);

/*
 * Class:     Musig2
 * Method:    get_signature
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_get_1signature
  (JNIEnv *, jclass, jstring);

/*
 * Class:     Musig2
 * Method:    get_key_agg
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_get_1key_1agg
  (JNIEnv *, jclass, jstring);

/*
 * Class:     Musig2
 * Method:    generate_threshold_pubkey
 * Signature: (Ljava/lang/String;J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_generate_1threshold_1pubkey
  (JNIEnv *, jclass, jstring, jlong);

/*
 * Class:     Musig2
 * Method:    generate_control_block
 * Signature: (Ljava/lang/String;JLjava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_Musig2_generate_1control_1block
  (JNIEnv *, jclass, jstring, jlong, jstring);

#ifdef __cplusplus
}
#endif
#endif
