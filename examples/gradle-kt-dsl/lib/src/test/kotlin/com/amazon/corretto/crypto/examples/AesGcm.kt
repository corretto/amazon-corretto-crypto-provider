package com.amazon.corretto.crypto.examples

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider
import java.nio.charset.Charset
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals

fun SecureRandom.randomSeq(len: Int): ByteArray {
    val result = ByteArray(len)
    this.nextBytes(result)
    return result
}

class AesGcm {
    @Test
    fun aesGcmEncryptDecrypt() {
        val accpProviderName = "AmazonCorrettoCryptoProvider"
        AmazonCorrettoCryptoProvider.install()
        val secureRandom = SecureRandom()
        assertEquals(accpProviderName, secureRandom.provider.name)
        val iv = secureRandom.randomSeq(12)
        val tagLenInBits = 128
        val gcmParameterSpec = GCMParameterSpec(tagLenInBits, iv)
        val secretKey = SecretKeySpec(secureRandom.randomSeq(32), "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        assertEquals(accpProviderName, cipher.provider.name)
        val message = "Hello World!"
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec)
        val cipherText = cipher.doFinal(message.toByteArray())

        assertEquals(message.length + (tagLenInBits / 8), cipherText.size)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec)

        val plainText = String(cipher.doFinal(cipherText), Charset.defaultCharset())
        assertEquals(message, plainText)
    }
}
