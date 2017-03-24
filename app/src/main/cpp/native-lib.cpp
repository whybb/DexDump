#include <jni.h>
#include <string>
#include <android/log.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#define TAG    "native"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)


extern "C"
{
JNIEXPORT jint JNICALL
Java_com_example_wings_dexdump_NativeTool_Dump(JNIEnv *env, jclass type, jstring str_) {
    const char *str = env->GetStringUTFChars(str_, 0);
    // TODO
    int result = 1;
    LOGD(" pakagenameis : %s", str);
    env->ReleaseStringUTFChars(str_, str);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_example_wings_dexdump_NativeTool_stringFromJNI(JNIEnv *env, jclass type) {

    // TODO
    std::string hello = "Hello from C++";

    return env->NewStringUTF(hello.c_str());
}

jstring
Java_com_example_wings_dexdump_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
}