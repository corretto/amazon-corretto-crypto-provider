#include <jni.h>
#include <openssl/crypto.h>


extern "C" JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_SelfTestSuite_awsLcSelfTestsPassed(JNIEnv*, jclass)
{
    return BORINGSSL_self_test() == 1 ? JNI_TRUE : JNI_FALSE;
}
