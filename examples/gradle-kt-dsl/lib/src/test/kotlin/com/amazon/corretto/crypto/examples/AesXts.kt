package com.amazon.corretto.crypto.examples

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

fun SecureRandom.genAesXtsKey(): SecretKeySpec {
    // AES-XTS expects the key size be 64 bytes
    val result = this.randomSeq(64)
    // The name of the algorithm is not important. ACCP needs the key to be
    // transparent and have 64 bytes.
    return SecretKeySpec(result, "AES-XTS")
}

fun SecureRandom.genRandTweak(): IvParameterSpec {
    // AES-XTS expects a tweak for encryption and decryption.
    // The tweak is 16 bytes and must be passed to cipher object
    // as an instance of IvParameterSpec
    val result = this.randomSeq(16)
    return IvParameterSpec(result)
}

class AesXts {
    @Test
    fun aesXtsExample() {
        val provider = AmazonCorrettoCryptoProvider.INSTANCE
        AmazonCorrettoCryptoProvider.install()
        val srand = SecureRandom()
        assertEquals(provider.name, srand.provider.name)
        val key = srand.genAesXtsKey()
        val tweak = srand.genRandTweak()
        // AES-XTS expects its input data to have at least 16 bytes
        val buffer = srand.randomSeq(18)
        println(" InputText: " + buffer.toHex())
        val expectedInput = buffer.clone()
        val cipher = Cipher.getInstance("AES/XTS/NoPadding", provider)
        cipher.init(Cipher.ENCRYPT_MODE, key, tweak)
        // the same buffer can be used for encryption and decryption
        val cipherLen = cipher.doFinal(buffer, 0, buffer.size, buffer)
        assertEquals(buffer.size, cipherLen)
        println("CipherText: " + buffer.toHex())
        cipher.init(Cipher.DECRYPT_MODE, key, tweak)
        // AES-XTS does not support multi-part enc/dec. One can only use doFinal methods.
        val plainText = cipher.doFinal(buffer)
        assertContentEquals(expectedInput, plainText)
        println(" PlainText: " + plainText.toHex())
    }
}
