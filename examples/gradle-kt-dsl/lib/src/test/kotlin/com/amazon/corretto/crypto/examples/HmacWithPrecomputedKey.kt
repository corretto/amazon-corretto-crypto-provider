package com.amazon.corretto.crypto.examples

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class HmacWithPrecomputedKey {
    @Test
    fun hmacWithPrecomputedKeyTest() {
        // EXPERT-ONLY use
        // This example is most likely NOT what you want to use.
        // If you need to use Hmac, see the Hmac.kt example.
        // This example shows how to use precomputed keys, which is not standard in JCA/JCE.
        // See ACCP README.md for details.

        val accpProviderName = "AmazonCorrettoCryptoProvider"
        AmazonCorrettoCryptoProvider.install()

        val mac = Mac.getInstance("HmacSHA384WithPrecomputedKey")
        assertEquals(accpProviderName, mac.provider.name)

        val skf = SecretKeyFactory.getInstance("HmacSHA384WithPrecomputedKey")
        assertEquals(accpProviderName, skf.provider.name)

        // An arbitrary 32-bytes key in base64 for the example
        val keyBase64 = "62lKZjLXnX4yGvNyd3/M3q+T6yfREHgbIoJidXCEzGw=";
        val key = Base64.getDecoder().decode(keyBase64);
        val keySpec = SecretKeySpec(key, "Generic");

        val message = "Hello, this is just an example."

        // Compute the HMAC precomputed key
        val precomputedKey = skf.generateSecret(keySpec)

        // Compute the HMAC using the precomputed key
        mac.init(precomputedKey);
        val macResult = mac.doFinal(message.toByteArray())

        // Verify the result matches what we expect
        val expectedResultBase64 =
            "w72DBgWvjTDqlv+EzOc1/R+K9Qq1jrNCHCQewXXhaOQ8Joi2jPPQdAT+HDc65KMM"
        val expectedResult = Base64.getDecoder().decode(expectedResultBase64)
        assertContentEquals(expectedResult, macResult)
    }
}