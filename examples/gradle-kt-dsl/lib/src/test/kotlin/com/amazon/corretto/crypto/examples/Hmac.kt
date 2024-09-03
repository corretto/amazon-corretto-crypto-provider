package com.amazon.corretto.crypto.examples

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class Hmac {
    @Test
    fun hmacTest() {
        val accpProviderName = "AmazonCorrettoCryptoProvider"
        AmazonCorrettoCryptoProvider.install()

        val mac = Mac.getInstance("HmacSHA384")
        assertEquals(accpProviderName, mac.provider.name)

        // An arbitrary 32-bytes key in base64 for the example
        val keyBase64 = "62lKZjLXnX4yGvNyd3/M3q+T6yfREHgbIoJidXCEzGw="
        val key = Base64.getDecoder().decode(keyBase64)
        val keySpec = SecretKeySpec(key, "Generic")

        val message = "Hello, this is just an example."

        // Compute the MAC
        mac.init(keySpec);
        val macResult = mac.doFinal(message.toByteArray())

        // Verify the result matches what we expect
        val expectedResultBase64 =
            "w72DBgWvjTDqlv+EzOc1/R+K9Qq1jrNCHCQewXXhaOQ8Joi2jPPQdAT+HDc65KMM"
        val expectedResult = Base64.getDecoder().decode(expectedResultBase64)
        assertContentEquals(expectedResult, macResult)
    }
}