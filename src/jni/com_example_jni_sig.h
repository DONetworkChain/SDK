/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_example_jni_sig */
#ifndef _Included_com_example_jni_sig
#define _Included_com_example_jni_sig
#ifdef __cplusplus

extern "C" {
#endif
/*
 * Class:    
 * Method:    importPkey
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_example_jni_sig_importPkey
  (JNIEnv *, jobject, jstring);

/*
 * Class:    
 * Method:    newPkey
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_newPkey
  (JNIEnv *, jobject);

/*
 * Class:     
 * Method:    sigmessage
 * Signature: (JLjava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_sigmessage
  (JNIEnv *, jobject, jlong, jstring);

/*
 * Class:     
 * Method:    vefmessage
 * Signature: (JLjava/lang/String;Ljava/lang/String;)Z
 */
JNIEXPORT jboolean JNICALL Java_com_example_jni_sig_vefmessage
  (JNIEnv *, jobject, jlong, jstring, jstring);

/*
 * Class:    
 * Method:    sigTx
 * Signature: (JLjava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_sigTx
  (JNIEnv *, jobject, jlong, jstring);

/*
 * Class:     
 * Method:    GetAddr
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_GetAddr
  (JNIEnv *, jobject, jlong);

/*
 * Class:     
 * Method:    GetPubStr
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_GetPubStr
  (JNIEnv *, jobject, jlong);

JNIEXPORT jstring JNICALL Java_com_example_jni_sig_signContractMessageTx
  (JNIEnv *, jobject, jlong,jstring);
  /*
 * Class:     src_sig_sig
 * Method:    ExportPriHexStr
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_ExportPriHexStr
  (JNIEnv *, jobject, jlong);

/*
 * Class:     src_sig_sig
 * Method:    ImportPriHexStr
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_example_jni_sig_ImportPriHexStr
  (JNIEnv *, jobject, jstring);

/*
 * Class:     src_sig_sig
 * Method:    ExportMnemoic
 * Signature: (J)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_ExportMnemoic
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     src_sig_sig
 * Method:    ImportMnemoic
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jbyteArray JNICALL Java_com_example_jni_sig_ImportMnemoic
  (JNIEnv *, jobject, jstring);


JNIEXPORT jstring JNICALL Java_com_example_jni_sig_getPubStringBase64
  (JNIEnv *, jobject, jlong);



  /*
 * Class:     src_sig_sig
 * Method:    Base64Encode
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_Base64Encode
  (JNIEnv *, jobject, jstring);

/*
 * Class:     src_sig_sig
 * Method:    Base64Decode
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_jni_sig_Base64Decode
  (JNIEnv *, jobject, jstring);

JNIEXPORT jstring JNICALL Java_com_example_jni_sig_GetContractPubStr
 (JNIEnv *env, jobject, jlong pkey);

JNIEXPORT void JNICALL Java_com_example_jni_sig_freePrikey
        (JNIEnv *env, jobject, jlong pkey);

JNIEXPORT jstring JNICALL Java_com_example_jni_sig_sigMessage
        (JNIEnv *env, jobject, jlong pkey, jstring message);

/*
 * Class:     src_sig_sig
 * Method:    importPkeybyseed
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_example_jni_sig_importSeed
  (JNIEnv * env, jobject, jbyteArray str);

/*
 * Class:     src_sig_sig
 * Method:    newPkeybyseed
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jbyteArray JNICALL Java_com_example_jni_sig_newSeed
  (JNIEnv *env , jobject);

JNIEXPORT jlong JNICALL Java_com_example_jni_private_key_check
(JNIEnv *env,jobject,jstring prikey,jstring base58);
#ifdef __cplusplus
}
#endif
#endif
