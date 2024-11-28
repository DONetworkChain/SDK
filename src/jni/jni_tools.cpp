
#include "jni_tools.h"


std::string jstring2string(JNIEnv *env, jstring jStr) {
    if (!jStr)
        return "";

    const jclass stringClass = env->GetObjectClass(jStr);
    const jmethodID getBytes = env->GetMethodID(stringClass, "getBytes", "(Ljava/lang/String;)[B");
    const jbyteArray stringJbytes = (jbyteArray) env->CallObjectMethod(jStr, getBytes, env->NewStringUTF("UTF-8"));

    size_t length = (size_t) env->GetArrayLength(stringJbytes);
    jbyte* pBytes = env->GetByteArrayElements(stringJbytes, NULL);

    std::string ret = std::string((char *)pBytes, length);
    env->ReleaseByteArrayElements(stringJbytes, pBytes, JNI_ABORT);

    env->DeleteLocalRef(stringJbytes);
    env->DeleteLocalRef(stringClass);
    return ret;
}

std::vector<uint8_t> jbytearray2vector(JNIEnv *env, jbyteArray jArr) {
    if (!jArr)
        return {};

    jsize length = env->GetArrayLength(jArr);
    jbyte* elements = env->GetByteArrayElements(jArr, nullptr);

    std::vector<uint8_t> result(elements, elements + length);

    env->ReleaseByteArrayElements(jArr, elements, JNI_ABORT);
    return result;
}