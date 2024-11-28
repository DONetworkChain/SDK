#include "com_example_jni_sig.h"
#include "debug.h"
#include "jni.h"
#include "sig.h"
#include "base64.h"
#include <string>
#include "jni_tools.h"
#include "sigTx.h"
#include "interface.h"
#include "Mac.h"
#include <iomanip>

/*
 * Class:     src_sig_sig
 * Method:    importPkey
 * Signature: (Ljava/lang/String;)J
 */
extern "C" JNIEXPORT jlong JNICALL Java_com_example_jni_sig_importPkey
  (JNIEnv * env, jobject, jstring str){
        std::string temp=jstring2string(env, str);
        Base64 base_;
        std::string prikey=base_.Decode(temp.c_str(), temp.size());
        void * pkey=ImportEVP_PKEY((const unsigned char *)prikey.c_str(),prikey.size());
        return (jlong)pkey;
  }

/*
 * Class:     src_sig_sig
 * Method:    newPkey
 * Signature: ()Ljava/lang/String;
 */
extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_newPkey
  (JNIEnv *env , jobject){
    unsigned char * buf_;
    int size=0;
    Base64 base_;
    std::string retvalue;
    bool ret=ExportEVP_PKEY(&buf_, &size);

    if(ret==false){
        errorL("ExportEVP_PKEY error");
       return  env->NewStringUTF("NULL");
        
    }
    retvalue=base_.Encode(buf_, size);
    //free(buf_);
    return env->NewStringUTF(retvalue.c_str());

  }

/*
 * Class:     src_sig_sig
 * Method:    sigmessage
 * Signature: (JLjava/lang/String;)Ljava/lang/String;
 */
extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_sigmessage
  (JNIEnv * env, jobject, jlong pkey, jstring message){
        void * pkey_t=(void *)pkey;
        std::string message_=jstring2string(env, message);
        unsigned char *signa=nullptr;
        int size=0;
        Base64 base_;
       bool ret_b= sig_((const void *)pkey_t,(const unsigned char *)message_.c_str(),message_.size(),&signa,&size);
        if(ret_b==false){
            errorL("sig_");
            return env->NewStringUTF("NULL");
        }
        std::string res=base_.Encode((const unsigned char *)signa,size);
        free(signa);
        return env->NewStringUTF(res.c_str());
  }

/*
 * Class:     src_sig_sig
 * Method:    vefmessage
 * Signature: (JLjava/lang/String;)Z
 */
extern "C" JNIEXPORT jboolean JNICALL Java_com_example_jni_sig_vefmessage
  (JNIEnv *env, jobject, jlong pkey, jstring message, jstring signature){
        Base64 base_;
        std::string temp=jstring2string(env, signature);
        std::string message_=jstring2string(env, message);
        std::string sign_=base_.Decode(temp.c_str(), temp.size());
        void * pkey_t=(void *)pkey;
        bool ret=verf_((const void *)pkey_t, (const unsigned char *)message_.c_str(), message_.size(), (unsigned char *)sign_.c_str(), sign_.size());
        return (jboolean)ret;
  }
  
  extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_sigTx(JNIEnv *env, jobject, jlong pkey, jstring tx)
  {
     std::string tx_t=jstring2string(env, tx);
     std::string res=toSig(tx_t,(void *) pkey);
      return env->NewStringUTF(res.c_str());
  }


  extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_GetAddr
  (JNIEnv *env , jobject, jlong pkey){
      return env->NewStringUTF(get_addr(pkey));
  }


  extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_GetPubStr
  (JNIEnv *env, jobject, jlong pkey){
       void * pkey_t=(void *)pkey;
       std::string ret=getPubStr(pkey_t);
       Base64 base_;
      std::string ep=  base_.Encode((const  unsigned char *)ret.c_str(), ret.size());
      return env->NewStringUTF(ep.c_str());
  }

/*
* Class:     src_sig_sig
* Method:    ExportPriHexStr
* Signature: (J)Ljava/lang/String;
*/
extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_ExportPriHexStr
        (JNIEnv *env, jobject, jlong pkey) {
    char *buf = nullptr;
    int size = 0;
    bool ret = ExportToHexStr((void *) pkey, &buf, &size);
    if (ret == false) {
        errorL("ExportToHexStr fail");
    }
    std::string buffer(buf, size);
    free(buf);
    return env->NewStringUTF(buffer.c_str());
}

/*
 * Class:     src_sig_sig
 * Method:    ImportPriHexStr
 * Signature: (Ljava/lang/String;)J
 */
extern "C" JNIEXPORT jlong JNICALL Java_com_example_jni_sig_ImportPriHexStr
        (JNIEnv *env, jobject, jstring hexStr) {
    std::string hexStr_s = jstring2string(env, hexStr);
    void *pkey = ImportFromHexStr(hexStr_s.c_str());
    return (jlong) pkey;
}

/*
 * Class:     src_sig_sig
 * Method:    ExportMnemoic
 * Signature: (J)Ljava/lang/String;
 */
extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_ExportMnemoic
        (JNIEnv *env, jobject, jbyteArray seed) {
    // Convert jbyteArray to std::vector<uint8_t>
    std::vector <uint8_t> seedVec = jbytearray2vector(env, seed);

    char *buf = nullptr;
    int size = 0;

    bool ret = ExportMnemonic(seedVec.data(), &buf, &size);
    if (ret == false) {
        errorL("ExportMnemonic fail");
    }
    // Convert the result to a Java string
    std::string mnemonic(buf, size);
    free(buf);
    return env->NewStringUTF(mnemonic.c_str());
}


/*
 * Class:     src_sig_sig
 * Method:    ImportMnemoic
 * Signature: (Ljava/lang/String;)J
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_example_jni_sig_ImportMnemoic
        (JNIEnv *env, jobject, jstring Mnstr) {
    // Convert jstring to std::string
    const char *MnstrChars = env->GetStringUTFChars(Mnstr, nullptr);
    std::string Mnestr(MnstrChars);
    env->ReleaseStringUTFChars(Mnstr, MnstrChars);

    // Call the ImportFromMnemonic method to process Mnestr
    uint8_t *tmpssd = (uint8_t *) ImportFromMnemonic(Mnestr.c_str());
    if(tmpssd == nullptr){
        return nullptr;
    }
    // Convert tmpssd to jbyteArray
    jbyteArray result = env->NewByteArray(PrimeSeedNum);
    env->SetByteArrayRegion(result, 0, PrimeSeedNum, reinterpret_cast<const jbyte *>(tmpssd));
    free(tmpssd);
    return result;
}


/*
* Class:     src_sig_sig
* Method:    Base64Encode
* Signature: (Ljava/lang/String;)Ljava/lang/String;
*/
extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_Base64Encode
        (JNIEnv *env, jobject, jstring str) {
    std::string res = jstring2string(env, str);
    Base64 base_;
    std::string ret = base_.Encode((const unsigned char *) res.c_str(), res.size());
    return env->NewStringUTF(ret.c_str());

}

/*
 * Class:     src_sig_sig
 * Method:    Base64Decode
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_Base64Decode
        (JNIEnv *env, jobject, jstring str) {

    std::string res = jstring2string(env, str);
    Base64 base_;
    std::string ret = base_.Decode((const char *) res.c_str(), res.size());
    return env->NewStringUTF(ret.c_str());

}

extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_GetContractPubStr
        (JNIEnv *env, jobject, jlong pkey) {
    char *buf = NULL;
    buf = get_pubstr_base64(pkey);
    std::string ep(buf);
    free(buf);
    return env->NewStringUTF(ep.c_str());
}
extern "C" JNIEXPORT void JNICALL Java_com_example_jni_sig_freePrikey
        (JNIEnv *env, jobject, jlong pkey) {
    free_prikey_handler(pkey);
}

//extern "C" JNIEXPORT jstring JNICALL Java_tfsc_wallet_sdk_Wallet4Android_signContractMessage
//        (JNIEnv *env, jobject, jlong pkey, jstring message) {
//    void *pkey_t = (void *) pkey;
//    std::string message_ = jstring2string(env, message);
//    unsigned char *signa = nullptr;
//    int size = 0;
//    Base64 base_;
//    bool ret_b = sig_contract_tx((const void *) pkey_t, (const unsigned char *) message_.c_str(),
//                                 message_.size(), &signa, &size);
//    if (ret_b == false) {
//        errorL("sig_");
//        return env->NewStringUTF("NULL");
//    }
//    std::string res = base_.Encode((const unsigned char *) signa, size);
//    free(signa);
//    return env->NewStringUTF(res.c_str());
//}

extern "C" JNIEXPORT jstring JNICALL Java_com_example_jni_sig_sigMessage
        (JNIEnv *env, jobject, jlong pkey, jstring message) {
    std::string message_ = jstring2string(env, message);
    char *signa = nullptr;
    int size = 0;
    bool ret_b = Sign(pkey, message_.c_str(),
                      message_.size(), &signa, &size);
    if (ret_b == false) {
        return env->NewStringUTF("NULL");
    }

    Base64 base_;
    std::string res = base_.Encode((const unsigned char *) signa, size);
    free(signa);

//    std::string resPub = getPubStr((const void *) pkey);
//    LOGD("resPub %s", resPub.c_str());
//    std::string ret = base_.Decode((const char *) res.c_str(), res.size());
//    LOGD("ret %s", ret.c_str());
//    LOGD("ret size  %d",ret.size());
//    bool ret_result = VerifByPublicStr(resPub.c_str(),resPub.size(),message_.c_str(),message_.size(),ret.c_str(),ret.size());
//    LOGD("ret_result %d", ret_result);

    return env->NewStringUTF(res.c_str());
}

/*
 * Class:     src_sig_sig
 * Method:    importPkey
 * Signature: (Ljava/lang/String;)J
 */
extern "C" JNIEXPORT jlong JNICALL Java_com_example_jni_sig_importSeed
  (JNIEnv * env, jobject, jbyteArray str){
    // Convert jbyteArray to std::vector<uint8_t>
    std::vector <uint8_t> prikey;
    jsize size = env->GetArrayLength(str);
    prikey.resize(size);
    env->GetByteArrayRegion(str,0, size, reinterpret_cast<jbyte*>(prikey.data()));
    // Call the GetPkeyBySeed method to handle prikey
    unsigned char *prikey_arr = reinterpret_cast<unsigned char *>(prikey.data());
    void *pkey = GetPkeyBySeed(prikey_arr, size);

    return reinterpret_cast<jlong>(pkey);
  }



/*
 * Class:     src_sig_sig
 * Method:    newPkey
 * Signature: ()Ljava/lang/String;
 */
extern "C" JNIEXPORT jbyteArray JNICALL Java_com_example_jni_sig_newSeed
  (JNIEnv *env , jobject)
{
    uint8_t *buf_;
    int size = 0;
    bool ret = ExportSeed(&buf_, &size);

    if (ret == false) {
        errorL("ExportEVP_PKEY error");
        return nullptr;
    }

    // Convert buf_ to jbyteArray
    jbyteArray result = env->NewByteArray(size);
    env->SetByteArrayRegion(result, 0, size, reinterpret_cast<const jbyte *>(buf_));
    free(buf_);

    return result;

}

// Converts a hexadecimal string to a char* array
extern "C" char *hexStringToChar(const std::string &hexString) {
    size_t length = hexString.length() / 2;
    char *output = new char[length + 1]; // Add 1 to add NULL ending characters
    for (size_t i = 0; i < length; ++i) {
        std::istringstream iss(hexString.substr(i * 2, 2));
        int value;
        iss >> std::hex >> value;
        output[i] = static_cast<char>(value);
    }
    output[length] = '\0'; // Add a NULL ending character
    return output;
}

// Converts a char* array to a hexadecimal string
extern "C" std::string charToHexString(const char *input, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
//        ss << std::setw(2) << std::uppercase << static_cast<unsigned int>(static_cast<unsigned char>(input[i]));
//        ss << std::setw(2) << std::tolower << static_cast<unsigned int>(static_cast<unsigned char>(input[i]));
//        ss << std::setw(2) << static_cast<char>(std::tolower(static_cast<unsigned char>(input[i])));
        ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(input[i]));
    }
    return ss.str();
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_tfsc_wallet_sdk_Wallet4Android_hexStringToByteArray(
        JNIEnv * env, jobject, jstring inputString) {

    // Get input string
    const char *hexChars = env->GetStringUTFChars(inputString, nullptr);
    if (hexChars == nullptr) {
        return nullptr; // Handle string fetch failure
    }
    // Calculates the length of a hexadecimal string
    size_t length = strlen(hexChars);
    // Converts the input string to a char* array
    char *inputChars = hexStringToChar(std::string(hexChars));
    // Converts a char* array to jbyteArray
    jbyteArray result = env->NewByteArray(length);
    env->SetByteArrayRegion(result,0, length, reinterpret_cast<const jbyte *>(inputChars));
    // Free memory
    delete[] inputChars;
    env-> ReleaseStringUTFChars(inputString, hexChars);
    return result;
}

extern "C" JNIEXPORT jstring JNICALL Java_tfsc_wallet_sdk_Wallet4Android_byteArrayToHexString(
        JNIEnv * env, jobject, jbyteArray inputArray) {
    // Get input array
    jsize size = env->GetArrayLength(inputArray);
    jbyte *inputBytes = env->GetByteArrayElements(inputArray, nullptr);
    if (inputBytes == nullptr) {
        return nullptr; // Handle array fetching failure
    }
    // Convert the jbyte* array to the char* array
    char *outputChars = convertUint8ToChar(reinterpret_cast<uint8_t *>(inputBytes), size);
    // Converts a char* array to a hexadecimal string
    std::string hexString = charToHexString(outputChars, size);
    // Free memory
    free(outputChars);
    env->ReleaseByteArrayElements(inputArray, inputBytes,JNI_ABORT);
    // Returns a hexadecimal string
    return env->NewStringUTF(hexString.c_str());
}

extern "C" JNIEXPORT jlong JNICALL Java_com_example_jni_private_key_check
(JNIEnv *env,jobject,jstring prikey,jstring base58)
{
    std::string strPrikey = jstring2string(env, prikey);
    std::string strBase58 = jstring2string(env, base58);
    
    char* c_prikey;
    int c_prikey_length = strPrikey.length(); // Get the length of the string
    c_prikey = new char[c_prikey_length + 1]; // Allocate memory for the char array (+1 for null terminator)
    std::strcpy(c_prikey, strPrikey.c_str());

    char* c_base58;
    int c_base58_length = strBase58.length(); // Get the length of the string
    c_base58 = new char[c_base58_length + 1]; // Allocate memory for the char array (+1 for null terminator)
    std::strcpy(c_base58, strBase58.c_str());

    int ret = isPrivateKeySame(c_prikey,c_prikey_length,c_base58);
    return (jlong)ret;
}