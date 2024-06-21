// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "env.h"
#include "generated-headers.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <vector>

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    buildCurve
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_buildGroup(JNIEnv* pEnv, jclass, jint nid)
{
    EC_GROUP* group;
    try {
        raii_env env(pEnv);

        if (unlikely(!(group = EC_GROUP_new_by_curve_name(nid)))) {
            throw_openssl("Unable to get group");
        }

        return (jlong)group;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    freeCurve
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_freeGroup(JNIEnv*, jclass, jlong group)
{
    EC_GROUP_free((EC_GROUP*)group);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    curveNameToInfo
 * Signature: (Ljava/lang/String;[B[B[B[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_curveNameToInfo(JNIEnv* pEnv,
    jclass,
    jstring curveName,
    jintArray mArr,
    jbyteArray pArr,
    jbyteArray aArr,
    jbyteArray bArr,
    jbyteArray cofactorArr,
    jbyteArray gxArr,
    jbyteArray gyArr,
    jbyteArray orderArr,
    jbyteArray oid,
    jbyteArray encoded)
{
    try {
        raii_env env(pEnv);

        if (!curveName) {
            throw_java_ex(EX_NPE, "Curve name must not be null");
        }
        jni_string jniCurve(env, curveName);

        int nid = OBJ_txt2nid(jniCurve.native_str);
        if (nid == NID_undef) {
            ERR_clear_error();
            return 0;
        }

        EC_GROUP_auto group = EC_GROUP_auto::from(EC_GROUP_new_by_curve_name(nid));
        if (unlikely(!group.isInitialized())) {
            unsigned long errCode = drainOpensslErrors();
            if (ERR_GET_LIB(errCode) == ERR_LIB_EC && ERR_GET_REASON(errCode) == EC_R_UNKNOWN_GROUP) {
                throw_java_ex(EX_ILLEGAL_ARGUMENT, "Unknown curve");
            } else {
                throw_java_ex(EX_RUNTIME_CRYPTO, formatOpensslError(errCode, "Unable to create group"));
            }
        }

        BigNumObj pBN;
        BigNumObj aBN;
        BigNumObj bBN;
        BigNumObj cfBN;
        BigNumObj gxBN;
        BigNumObj gyBN;
        BigNumObj orderBN;

        const EC_POINT* generator = NULL;

        if (EC_GROUP_get_cofactor(group, cfBN, NULL) != 1) {
            throw_openssl("Unable to get cofactor");
        }
        cfBN.toJavaArray(env, cofactorArr);

        generator = EC_GROUP_get0_generator(group);
        if (!generator) {
            throw_openssl("Unable to get generator");
        }

        if (EC_GROUP_get_curve_GFp(group, pBN, aBN, bBN, NULL) != 1) {
            throw_openssl("Unable to get group information");
        }
        if (EC_POINT_get_affine_coordinates_GFp(group, generator, gxBN, gyBN, NULL) != 1) {
            throw_openssl("Unable to get generator coordinates");
        }

        gxBN.toJavaArray(env, gxArr);
        gyBN.toJavaArray(env, gyArr);

        pBN.toJavaArray(env, pArr);
        aBN.toJavaArray(env, aArr);
        bBN.toJavaArray(env, bArr);

        if (EC_GROUP_get_order(group, orderBN, NULL) != 1) {
            throw_openssl("Unable to get group order");
        }
        orderBN.toJavaArray(env, orderArr);

        // Get the decoded (string) curve OID
        jni_borrow oidBorrow = jni_borrow(env, java_buffer::from_array(env, oid), "curveNameToInfo");
        if (!OBJ_obj2txt((char*)oidBorrow.data(), (int)oidBorrow.len(), OBJ_nid2obj(nid), /*always_return_oid*/ 1)) {
            throw_openssl("Unable to get decoded curve OID");
        }
        oidBorrow.release();

        // Get the DER-encoded curve OID
        jni_borrow encodedBorrow = jni_borrow(env, java_buffer::from_array(env, encoded), "curveNameToInfo");
        CBB cbb;
        CBB_init_fixed(&cbb, encodedBorrow.data(), encodedBorrow.len());
        if (!EC_KEY_marshal_curve_name(&cbb, group)) {
            throw_openssl("Unable to get encoded curve OID");
        }
        encodedBorrow.release();

        return nid;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    getCurveNames
 */
JNIEXPORT jobjectArray JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_getCurveNames(JNIEnv* pEnv, jclass)
{
    try {
        raii_env env(pEnv);

        std::vector<EC_builtin_curve> curves;
        // Specify 0 as the max return count so no data is written, but we get the curve count
        size_t numCurves = EC_get_builtin_curves(curves.data(), 0);
        // Now that we know the number of curves to expect, resize and get the curve info from LC
        curves.resize(numCurves);
        numCurves = EC_get_builtin_curves(curves.data(), curves.size());
        if (numCurves > curves.size()) {
            // We get curve count from LC and resize accordingly, so we should never hit this.
            throw_openssl("Too many curves");
        }

        jobjectArray names = env->NewObjectArray(numCurves, env->FindClass("java/lang/String"), nullptr);
        for (size_t i = 0; i < numCurves; i++) {
            // NOTE: we return the "short name" (e.g. secp384r1) rather than the NIST name (e.g. "NIST P-384")
            env->SetObjectArrayElement(names, i, env->NewStringUTF(OBJ_nid2sn(curves[i].nid)));
        }

        return names;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EcUtils
 * Method:    getCurveNameFromEncoded
 * Signature: ([B)Ljava/lang/String
 */
JNIEXPORT jstring JNICALL Java_com_amazon_corretto_crypto_provider_EcUtils_getCurveNameFromEncoded(
    JNIEnv* pEnv, jclass, jbyteArray encoded)
{
    try {
        raii_env env(pEnv);

        jni_borrow borrow = jni_borrow(env, java_buffer::from_array(env, encoded), "getCurveNameFromEncoded");
        CBS cbs;
        CBS_init(&cbs, borrow.data(), borrow.len());
        EC_GROUP* group = EC_KEY_parse_curve_name(&cbs);
        if (group == nullptr) {
            throw_openssl("Unable to parse curve OID ASN.1");
        }

        int nid = EC_GROUP_get_curve_name(group);
        if (nid == NID_undef) {
            throw_openssl("Unable to get curve nid from group");
        }
        // NOTE: we return the "short name" (e.g. secp384r1) rather than the NIST name (e.g. "NIST P-384")
        const char* shortName = OBJ_nid2sn(nid);
        if (shortName == nullptr) {
            throw_openssl("Unable to get short name from nid");
        }
        // NOTE: need to use the JNIEnv |pEnv| here instead of raii_env |env|
        // because we're returning the JString value and |env|'s dtor checks
        // for locks once it goes out of scope.
        return pEnv->NewStringUTF(shortName);
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return nullptr;
    }
}
