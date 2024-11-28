
#ifndef __JNI_TOOLS_
#define __JNI_TOOLS_
#include <jni.h>
#include <string>
#include <vector>
std::string jstring2string(JNIEnv *env, jstring jStr);
std::vector<uint8_t> jbytearray2vector(JNIEnv *env, jbyteArray jArr);
#endif