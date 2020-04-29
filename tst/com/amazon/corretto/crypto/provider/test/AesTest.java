// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assumeMinimumVersion;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyConstruct;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyGetField;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke;
import static com.amazon.corretto.crypto.provider.test.TestUtil.sneakyInvoke_int;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_REFLECTION)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ_WRITE)
public class AesTest {
    private static final Class<?> SPI_CLASS;
    private static final byte[] PLAINTEXT = "Hello world. Good night moon.".getBytes(StandardCharsets.UTF_8);
    private static final String ALGO_NAME = "AES/GCM/NoPadding";
    private static final String PROVIDER_SUN = "SunJCE";
    private static final String PROVIDER_AMAZON = "AmazonCorrettoCryptoProvider";
    private byte[] nonce;
    private SecretKeySpec key;
    private Cipher jceC;
    private Cipher amznC;

    static {
      try {
        SPI_CLASS = Class.forName("com.amazon.corretto.crypto.provider.AesGcmSpi");
      } catch (final ClassNotFoundException ex) {
        throw new AssertionError(ex);
      }
    }

    @BeforeAll
    public static void setupProvider() {
        Security.addProvider(AmazonCorrettoCryptoProvider.INSTANCE);
    }
    
    @BeforeEach
    public void setup() throws Throwable {
        byte[] foo = TestUtil.getRandomBytes(16);
        key = new SecretKeySpec(foo, "AES");
        nonce = TestUtil.getRandomBytes(12);
        jceC = Cipher.getInstance(ALGO_NAME);
        amznC = Cipher.getInstance(ALGO_NAME, AmazonCorrettoCryptoProvider.INSTANCE);
    }

    @AfterEach
    public void teardown() {
        // It is unclear if JUnit always properly releases references to classes and thus we may have memory leaks
        // if we do not properly null our references
        key = null;
        jceC = null;
        amznC = null;
        nonce = null;
    }

    private Object getSpiInstance() throws Throwable {
      return sneakyConstruct(SPI_CLASS.getName());
    }

    @Test
    public void jce2amzn() throws GeneralSecurityException {
        jceC.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] ciphertext = jceC.doFinal(PLAINTEXT);
        amznC.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        amznC.update(ciphertext);
        byte[] decrypted = amznC.doFinal();
        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    public void amzn2jce() throws GeneralSecurityException {
        amznC.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] ciphertext = amznC.doFinal(PLAINTEXT);
        jceC.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] decrypted = jceC.doFinal(ciphertext);
        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    public void amzn2jce_empty() throws GeneralSecurityException {
        amznC.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        amznC.update(new byte[0]);
        byte[] ciphertext = amznC.doFinal();
        jceC.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] decrypted = jceC.doFinal(ciphertext);
        assertArrayEquals(new byte[0], decrypted);
    }

    @Test
    public void amzn2jce_null() throws GeneralSecurityException {
        byte[] aad = new byte[64];
        amznC.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] ciphertext = new byte[nonce.length + 16];
        amznC.updateAAD(aad);
        amznC.update(new byte[0], 0, 0);
        int len = amznC.doFinal(ciphertext, 0);
        jceC.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        jceC.updateAAD(aad);
        jceC.update(ciphertext, 0, len);
        byte[] decrypted = jceC.doFinal();
        assertArrayEquals(new byte[0], decrypted);
    }

    @Test
    public void amzn2jce_nonatomic() throws Throwable {
        amznC.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        os.write(amznC.update(PLAINTEXT));
        os.write(amznC.doFinal());

        byte[] ciphertext = os.toByteArray();

        jceC.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] decrypted = jceC.doFinal(ciphertext);
        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    public void overlap_encrypt() throws Exception {
        for (int doUpdate = 0; doUpdate <= 1; doUpdate++) {
            for (int align = -32; align <= 32; align++) {
                // engineInit complains (and rightly so) if we reuse key and IV, so frob them here so the loop can go on
                nonce[0]++;

                byte[] plaintext = new byte[100];
                ThreadLocalRandom.current().nextBytes(plaintext);

                byte[] io_buffer = new byte[plaintext.length + 16 + Math.abs(align)];

                int outoffset, inoffset;
                if (align < 0) {
                    // Start the input before the output
                    inoffset = 0;
                    outoffset = -align;
                    System.arraycopy(plaintext, 0, io_buffer, 0, plaintext.length);
                } else {
                    inoffset = align;
                    outoffset = 0;
                    System.arraycopy(plaintext, 0, io_buffer, inoffset, plaintext.length);
                }

                // Test update into doFinal here
                amznC.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                int ciphertext_length;
                if (doUpdate > 0) {
                    ciphertext_length = amznC.update(io_buffer, inoffset, plaintext.length, io_buffer, outoffset);
                    ciphertext_length += amznC.doFinal(io_buffer, inoffset + plaintext.length, 0, io_buffer,
                                                       outoffset + ciphertext_length);
                } else {
                    ciphertext_length = amznC.doFinal(io_buffer, inoffset, plaintext.length, io_buffer, outoffset);
                }

                // Now put it back where it was before
                amznC.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                int plaintextlen = amznC.doFinal(io_buffer, outoffset, ciphertext_length, io_buffer, inoffset);

                assertArrayEquals(plaintext, Arrays.copyOfRange(io_buffer, inoffset, plaintextlen + inoffset));
            }
        }
    }

    @Test
    public void large_overlap_encrypt() {
        // modes:
        //   0 = use doFinal on byte arrays;
        //   1 = use update then doFinal on byte arrays;
        //   2 = use update on bytebufs
        //   3 = use update on RO input bytebuf; disable reflective access
        for (int mode = 0; mode < 4; mode++) {
            try {
                // We construct a test case where the output pointer is ahead of the input pointer by an amount larger than
                // CHUNK_SIZE. This would force us to buffer much more than we normally would in order to avoid trashing later
                // input.

                // inptr = 0, outptr = 1MB, length = 2MB.
                byte[] buf = new byte[4 * 1024 * 1024];
                ThreadLocalRandom.current().nextBytes(buf);
                byte[] plaintext = Arrays.copyOfRange(buf, 0, 2 * 1024 * 1024);

                int inptr = 0;
                int outptr = 1024 * 1024;

                // frob IV to avoid complaints from engineInit
                nonce[0]++;

                amznC.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));

                int ciphertext_len;
                switch (mode) {
                    case 0:
                        ciphertext_len = amznC.doFinal(buf, inptr, plaintext.length, buf, outptr);
                        break;
                    case 1:
                        ciphertext_len = amznC.update(buf, inptr, plaintext.length, buf, outptr);
                        ciphertext_len += amznC.doFinal(buf, inptr + plaintext.length, 0, buf, outptr + ciphertext_len);
                        break;
                    case 2:
                        ciphertext_len = amznC.update(
                                ByteBuffer.wrap(buf, inptr, plaintext.length),
                                ByteBuffer.wrap(buf, outptr, plaintext.length + 16)
                        );
                        ciphertext_len += amznC.doFinal(buf, inptr + plaintext.length, 0, buf, outptr + ciphertext_len);
                        break;
                    case 3:
                        TestUtil.disableByteBufferReflection();

                        try {
                            ciphertext_len = amznC.update(
                                    ByteBuffer.wrap(buf, inptr, plaintext.length).asReadOnlyBuffer(),
                                    ByteBuffer.wrap(buf, outptr, plaintext.length + 16)
                            );
                            ciphertext_len += amznC.doFinal(buf, inptr + plaintext.length, 0, buf,
                                                            outptr + ciphertext_len);
                        } finally {
                            TestUtil.enableByteBufferReflection();
                        }
                        break;
                    default:
                        throw new UnsupportedOperationException();
                }

                // make sure one-shot decrypt works okay too
                System.arraycopy(buf, outptr, buf, inptr, ciphertext_len);
                amznC.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));

                int plaintextlen = amznC.doFinal(buf, inptr, ciphertext_len, buf, outptr);

                assertArrayEquals(plaintext, Arrays.copyOfRange(buf, outptr, outptr + plaintextlen));
            } catch (Throwable t) {
                throw new RuntimeException("Error in mode " + mode, t);
            }
        }

    }

    @Test
    public void edge_badSetMode() throws Throwable {
        assertThrows(NoSuchAlgorithmException.class, () ->
            sneakyInvoke(getSpiInstance(), "engineSetMode", "ECB"));
    }

    @Test
    public void edge_correctSetMode() throws Throwable {
        sneakyInvoke(getSpiInstance(), "engineSetMode", "GCM");
        sneakyInvoke(getSpiInstance(), "engineSetMode", "gcm");
    }

    @Test
    public void edge_badSetPadding() throws Throwable {
        assertThrows(NoSuchPaddingException.class, () ->
            sneakyInvoke(getSpiInstance(), "engineSetPadding", "PKCS5Padding"));
    }

    @Test
    public void edge_correctSetPadding() throws Throwable {
        sneakyInvoke(getSpiInstance(), "engineSetPadding", "NoPadding");
        sneakyInvoke(getSpiInstance(), "engineSetPadding", "nopadding");
    }

    @Test
    public void edge_badParameters() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> sneakyInvoke(getSpiInstance(), "engineInit", 9999, key, new GCMParameterSpec(128, randomIV()), rnd));

        assertThrows(
                InvalidKeyException.class,
                () -> sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[1], "AES"),
                        new GCMParameterSpec(128, randomIV()), rnd));

        assertThrows(InvalidKeyException.class,
                () -> sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[16], "RC4"),
                        new GCMParameterSpec(128, randomIV()), rnd));

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE,
                        key,
                        new GCMParameterSpec(127, randomIV()), rnd));

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE,
                        key,
                        new GCMParameterSpec(136, randomIV()), rnd));

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE,
                        key,
                        new GCMParameterSpec(88, randomIV()), rnd));

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE,
                        key,
                        new GCMParameterSpec(128, new byte[0]), rnd));

        // Check supported lengths
        sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(96, randomIV()), rnd);
        sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(104, randomIV()), rnd);
        sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(112, randomIV()), rnd);
        sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(120, randomIV()), rnd);
        sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> sneakyInvoke(getSpiInstance(), "engineInit", Cipher.ENCRYPT_MODE, key,
                        new DHParameterSpec(BigInteger.ONE, BigInteger.ONE, 1), rnd));
    }

    @Test
    public void test_engineGetKeySize() throws Throwable {
        final SecretKeySpec key128 = new SecretKeySpec(new byte[16], "AES");
        final SecretKeySpec key256 = new SecretKeySpec(new byte[32], "AES");

        final Object aesGcmSpi = getSpiInstance();
        assertEquals(128, sneakyInvoke_int(aesGcmSpi, "engineGetKeySize", key128));
        assertEquals(256, sneakyInvoke_int(aesGcmSpi, "engineGetKeySize", key256));
    }

    @Test
    public void detail_blockSize() throws Throwable {
        assertEquals(128 / 8, sneakyInvoke_int(getSpiInstance(), "engineGetBlockSize"));
    }

    @Test
    public void test_getOutputSize_decrypt() throws Throwable {
      Object spi = getSpiInstance();

        sneakyInvoke(spi, "engineInit", Cipher.DECRYPT_MODE, key,
                new GCMParameterSpec(12 * 8, new byte[16]), TestUtil.MISC_SECURE_RANDOM.get());

        assertEquals(12345 - 12, sneakyInvoke_int(spi, "engineGetOutputSize", 12345));
    }

    @Test
    public void test_getOutputSize_encrypt() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();
        Object spi = getSpiInstance();

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(16 * 8, randomIV()), rnd);

        // Allows room for the final tag
        assertEquals(12345 + 16, sneakyInvoke_int(spi, "engineGetOutputSize", 12345));

        // Allows room for a partial buffered block
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(12 * 8, randomIV()), rnd);
        assertEquals(12345 + 15, sneakyInvoke_int(spi, "engineGetOutputSize", 12345));
    }

    @Test
    public void test_getIV() throws Throwable {
      Object spi = getSpiInstance();
        byte[] iv = new byte[16];

        ThreadLocalRandom.current().nextBytes(iv);

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(16 * 8, iv), TestUtil.MISC_SECURE_RANDOM.get());

        assertArrayEquals(iv, sneakyInvoke(spi, "engineGetIV"));
    }

    @Test
    public void test_getParameters() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();
        Object spi = getSpiInstance();
        byte[] iv = new byte[16];
        ThreadLocalRandom.current().nextBytes(iv);

        GCMParameterSpec spec = new GCMParameterSpec(12 * 8, iv);
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key, spec, rnd);

        AlgorithmParameters parameters = sneakyInvoke(spi, "engineGetParameters");
        GCMParameterSpec actualSpec = parameters.getParameterSpec(GCMParameterSpec.class);
        assertArrayEquals(spec.getIV(), actualSpec.getIV());
        assertEquals(spec.getTLen(), actualSpec.getTLen());

        assumeMinimumVersion("1.0", AmazonCorrettoCryptoProvider.INSTANCE);
        ThreadLocalRandom.current().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key, ivSpec, rnd);

        parameters = sneakyInvoke(spi, "engineGetParameters");
        actualSpec = parameters.getParameterSpec(GCMParameterSpec.class);
        assertArrayEquals(ivSpec.getIV(), actualSpec.getIV());
        // Default tag length is 128
        assertEquals(128, actualSpec.getTLen());

    }

    @Test
    public void test_initImplicit() throws Throwable {
        amznC.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = amznC.doFinal(PLAINTEXT);

        jceC.init(Cipher.DECRYPT_MODE, key, amznC.getParameters());
        byte[] decrypted = jceC.doFinal(ciphertext);

        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    public void test_initImplicit_returnsNewIV() throws Throwable {
        amznC.init(Cipher.ENCRYPT_MODE, key);
        GCMParameterSpec parms1 = amznC.getParameters().getParameterSpec(GCMParameterSpec.class);

        amznC.init(Cipher.ENCRYPT_MODE, key);
        GCMParameterSpec parms2 = amznC.getParameters().getParameterSpec(GCMParameterSpec.class);

        assertFalse(Arrays.equals(parms1.getIV(), parms2.getIV()));
    }

    @Test
    public void test_initParameters() throws Throwable {
        jceC.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = jceC.doFinal(PLAINTEXT);

        amznC.init(Cipher.DECRYPT_MODE, key, jceC.getParameters());
        byte[] decrypted = amznC.doFinal(ciphertext);

        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    public void test_bufferOverflows() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Object spi = getSpiInstance();
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);

        // Bad output arrays on doFinal
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ShortBufferException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", new byte[1], 0, 1, new byte[0], 0));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ShortBufferException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", new byte[1], 0, 1, new byte[256], 255));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", new byte[1], 0, 1, new byte[256], -1));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ShortBufferException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", new byte[1024], 0, 1024, new byte[256], 0));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ShortBufferException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", ByteBuffer.allocate(1024), ByteBuffer.allocate(0)));

        // Bad input arrays on doFinal
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", new byte[1], 0, 2, new byte[256], 0));
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", new byte[1], -1, 1, new byte[256], 0));
        // Integer overflow
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", new byte[256], 0xFFFFFFF0, 0x20, new byte[256], 0));

        // Short output arrays on update()
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ShortBufferException.class,
                () -> sneakyInvoke(spi, "engineUpdate", new byte[16], 0, 16, new byte[15], 0));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ShortBufferException.class,
                () -> sneakyInvoke(spi, "engineUpdate", new byte[16], 0, 16, new byte[32], 16));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineUpdate", new byte[16], 0, 16, new byte[32], -1));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ShortBufferException.class,
                () -> sneakyInvoke(spi, "engineUpdate", new byte[1024], 0, 1024, new byte[32], 0));
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ShortBufferException.class,
                () -> sneakyInvoke(spi, "engineUpdate", ByteBuffer.allocate(1024), ByteBuffer.allocate(0)));

        // Input array issues on update()
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineUpdate", new byte[16], 0, 17, new byte[1024], 0));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineUpdate", new byte[16], 0, -1, new byte[1024], 0));

        // Integer overflow
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineUpdate", new byte[16], 0xFFFFFFF0, 0x20, new byte[1024], 0));

        // AAD buffer issues
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineUpdateAAD", new byte[16], 0, 17));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineUpdateAAD", new byte[16], 0, -1));

        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, randomIV()), rnd);
        assertThrows(ArrayIndexOutOfBoundsException.class,
                () -> sneakyInvoke(spi, "engineUpdateAAD", new byte[16], 0xFFFFFFF0, 0x20));
    }

    @Test
    public void whenIVReused_throws() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Object spi = getSpiInstance();
        sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[16]), rnd);

        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> sneakyInvoke(spi, "engineInit", Cipher.ENCRYPT_MODE, key,
                        new GCMParameterSpec(128, new byte[16]), rnd));
    }

    @Test
    public void whenAADTagSetAfterInit_throws() throws Throwable {
        // COMPATIBILITY: SunJCE accepts updateAAD after update(), despite updateAAD being
        // documented as throwing
        // IllegalStateException when called after update(). We implement the javadoc'd behavior.
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();


        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[16]), rnd);

        c.update(new byte[1]);

        assertThrows(IllegalStateException.class, () ->  c.updateAAD(new byte[1]));
    }

    @Test
    public void testBadAEADTagException() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_SUN);
        GCMParameterSpec algorithmParameterSpec = new GCMParameterSpec(128, randomIV());
        c.init(Cipher.ENCRYPT_MODE, key, algorithmParameterSpec, rnd);

        byte[] data = c.doFinal(randomIV());

        for (int bit = 0; bit < data.length * 8; bit++) {
            byte[] corruptData = data.clone();
            corruptData[bit / 8] ^= (1 << (bit % 8));

            Cipher check = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
            check.init(Cipher.DECRYPT_MODE, key, algorithmParameterSpec, rnd);

            assertThrows(AEADBadTagException.class, () -> check.doFinal(corruptData));
        }
    }

    @Test
    public void whenCipherReusedWithoutReinit_throwsIVReuseException() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, randomIV()), rnd);
        c.doFinal();
        assertThrows(IllegalStateException.class, c::doFinal);
    }

    @Test
    public void whenDecryptModeReused_noException() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_SUN);
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, randomIV()), rnd);

        byte[] data = c.doFinal();

        Cipher d = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        d.init(Cipher.DECRYPT_MODE, key, c.getParameters(), rnd);
        d.doFinal(data);
        d.doFinal(data);
    }

    @Test
    public void whenDoFinalWithoutInit_throwsCorrectException() throws Throwable {
        assertThrows(IllegalStateException.class, () ->
            sneakyInvoke(getSpiInstance(), "engineDoFinal", new byte[0], 0, 0, new byte[16], 0));
    }

    @Test
    public void testLargeIVs() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[1024 * 1024]), rnd);
    }

    @Test
    public void testLargeAAD_decrypt() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_SUN);
        byte[] aad = new byte[1024 * 1024]; // new byte[1024*1024];
        byte[] data = new byte[1024 * 1024];

        GCMParameterSpec params = new GCMParameterSpec(128, randomIV());

        ThreadLocalRandom.current().nextBytes(aad);
        ThreadLocalRandom.current().nextBytes(data);

        c.init(Cipher.ENCRYPT_MODE, key, params, rnd);
        c.updateAAD(aad);
        byte[] ciphertext = c.doFinal(data);

        Cipher c2 = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        c2.init(Cipher.DECRYPT_MODE, key, params, rnd);
        c2.updateAAD(aad);
        byte[] plaintext = c2.doFinal(ciphertext);

        assertArrayEquals(data, plaintext);

        // AAD data must be considered when decrypting
        aad[1024 * 1024 - 1]++;
        c2.init(Cipher.DECRYPT_MODE, key, params, rnd);
        c2.updateAAD(aad);
        assertThrows(AEADBadTagException.class, () -> c2.doFinal(ciphertext));
    }

    @Test
    public void testLargeAAD_encrypt() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        byte[] aad = new byte[1024 * 1024]; // new byte[1024*1024];
        byte[] data = new byte[1024 * 1024];

        GCMParameterSpec params = new GCMParameterSpec(128, randomIV());

        ThreadLocalRandom.current().nextBytes(aad);
        ThreadLocalRandom.current().nextBytes(data);

        c.init(Cipher.ENCRYPT_MODE, key, params, rnd);
        c.updateAAD(aad);
        byte[] ciphertext = c.doFinal(data);

        Cipher c2 = Cipher.getInstance(ALGO_NAME, PROVIDER_SUN);
        c2.init(Cipher.DECRYPT_MODE, key, params, rnd);
        c2.updateAAD(aad);
        byte[] plaintext = c2.doFinal(ciphertext);

        assertArrayEquals(data, plaintext);
    }

    @Test
    public void testUninitializedCipher() throws Throwable {
        Object spi = getSpiInstance();

        assertThrows(IllegalStateException.class, () -> sneakyInvoke(spi, "engineDoFinal", new byte[0], 0, 0));
        assertThrows(IllegalStateException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", new byte[0], 0, 0, new byte[256], 0));
        assertThrows(IllegalStateException.class,
                () -> sneakyInvoke(spi, "engineDoFinal", ByteBuffer.allocate(0), ByteBuffer.allocate(256)));

        assertThrows(IllegalStateException.class, () -> sneakyInvoke(spi, "engineUpdate", new byte[0], 0, 0));
        assertThrows(IllegalStateException.class,
                () -> sneakyInvoke(spi, "engineUpdate", new byte[0], 0, 0, new byte[256], 0));
        assertThrows(IllegalStateException.class,
                () -> sneakyInvoke(spi, "engineUpdate", ByteBuffer.allocate(0), ByteBuffer.allocate(256)));

        assertThrows(IllegalStateException.class, () -> sneakyInvoke(spi, "engineUpdateAAD", new byte[0], 0, 0));
        assertThrows(IllegalStateException.class, () -> sneakyInvoke(spi, "engineUpdateAAD", ByteBuffer.allocate(0)));

        assertThrows(IllegalStateException.class, () -> sneakyInvoke(spi, "engineGetOutputSize", 0));
    }

    @Test
    public void testShortArrays() throws Throwable {
        final SecureRandom rnd = TestUtil.MISC_SECURE_RANDOM.get();

        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]), rnd);

        assertThrows(AEADBadTagException.class, "Input too short - need tag", () -> c.doFinal());
        assertThrows(AEADBadTagException.class, "Input too short - need tag", () -> c.doFinal(new byte[0]));
        assertThrows(AEADBadTagException.class, "Input too short - need tag", () -> c.doFinal(new byte[1]));
        assertThrows(AEADBadTagException.class, "Input too short - need tag", () -> c.doFinal(new byte[15]));

        c.updateAAD(new byte[16]);
        assertThrows(AEADBadTagException.class, "Input too short - need tag", () -> c.doFinal());
        c.updateAAD(new byte[16]);
        assertThrows(AEADBadTagException.class, "Input too short - need tag", () -> c.doFinal(new byte[0]));
        c.updateAAD(new byte[16]);
        assertThrows(AEADBadTagException.class, "Input too short - need tag", () -> c.doFinal(new byte[1]));
        c.updateAAD(new byte[16]);
        assertThrows(AEADBadTagException.class, "Input too short - need tag", () -> c.doFinal(new byte[15]));
    }

    @Test
    public void testEmptyPlaintext() throws Throwable {
        GCMParameterSpec spec = new GCMParameterSpec(128, randomIV());
        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext = c.doFinal();
        c.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] plaintext = c.doFinal(ciphertext);
        assertArrayEquals(new byte[0], plaintext);

        spec = new GCMParameterSpec(128, randomIV());
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        c.updateAAD(PLAINTEXT);
        ciphertext = c.doFinal();
        c.init(Cipher.DECRYPT_MODE, key, spec);
        c.updateAAD(PLAINTEXT);
        plaintext = c.doFinal(ciphertext);
        assertArrayEquals(new byte[0], plaintext);
    }

    @Test
    public void safeReuse() throws Throwable {
        Cipher c = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
        final Object spi = sneakyGetField(c, "spi");
        final int keyReuseThreshold = (int) sneakyGetField(spi.getClass(), "KEY_REUSE_THRESHOLD");
        assertEquals(1, keyReuseThreshold, "Test must be re-written for KEY_REUSE_THRESHOLD != 1");

        GCMParameterSpec spec1 = new GCMParameterSpec(128, randomIV());
        GCMParameterSpec spec2 = new GCMParameterSpec(128, randomIV());
        GCMParameterSpec spec3 = new GCMParameterSpec(128, randomIV());

        final byte[] plaintext1 = "Hello world!".getBytes(StandardCharsets.UTF_8);
        final byte[] plaintext2 = "Goodbye world!".getBytes(StandardCharsets.UTF_8);
        final byte[] plaintext3 = "Where am I anyway?".getBytes(StandardCharsets.UTF_8);

        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNull(sneakyGetField(spi, "context"));
        // Encrypt then decrypt
        c.init(Cipher.ENCRYPT_MODE, key, spec1);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNull(sneakyGetField(spi, "context"));
        byte[] ciphertext1 = c.doFinal(plaintext1);
        c.init(Cipher.ENCRYPT_MODE, key, spec2);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNull(sneakyGetField(spi, "context"));
        byte[] ciphertext2 = c.doFinal(plaintext2);
        c.init(Cipher.ENCRYPT_MODE, key, spec3);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        byte[] ciphertext3 = c.doFinal(plaintext3);

        c.init(Cipher.DECRYPT_MODE, key, spec1);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        assertArrayEquals(plaintext1, c.doFinal(ciphertext1));
        c.init(Cipher.DECRYPT_MODE, key, spec2);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        assertArrayEquals(plaintext2, c.doFinal(ciphertext2));
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        c.init(Cipher.DECRYPT_MODE, key, spec3);
        assertArrayEquals(plaintext3, c.doFinal(ciphertext3));

        // Interleaved
        c.init(Cipher.ENCRYPT_MODE, key, spec1);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        ciphertext1 = c.doFinal(plaintext1);
        c.init(Cipher.DECRYPT_MODE, key, spec1);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        assertArrayEquals(plaintext1, c.doFinal(ciphertext1));

        c.init(Cipher.ENCRYPT_MODE, key, spec2);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        ciphertext2 = c.doFinal(plaintext2);
        c.init(Cipher.DECRYPT_MODE, key, spec2);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        assertArrayEquals(plaintext2, c.doFinal(ciphertext2));

        c.init(Cipher.ENCRYPT_MODE, key, spec3);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        ciphertext3 = c.doFinal(plaintext3);
        c.init(Cipher.DECRYPT_MODE, key, spec3);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        assertArrayEquals(plaintext3, c.doFinal(ciphertext3));

        // Try a decrypt with the same key bytes but a different key object
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getEncoded(), key.getAlgorithm()), spec2);
        assertFalse((boolean) sneakyGetField(spi, "contextInitialized"));
        assertNotNull(sneakyGetField(spi, "context"));
        assertArrayEquals(plaintext2, c.doFinal(ciphertext2));
    }

    private byte[] randomIV() {
        return TestUtil.getRandomBytes(16);
    }

    @Test
    public void threadStorm() throws GeneralSecurityException, InterruptedException {
        final byte[] rngSeed = TestUtil.getRandomBytes(20);
        System.out.println("RNG Seed: " + Arrays.toString(rngSeed));
        final SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(rngSeed);
        final int iterations = 500;
        final int threadCount = 48;

        final SecretKey[] keys = new SecretKey[3];
        byte[] buff = new byte[32];
        rng.nextBytes(buff);
        keys[0] = new SecretKeySpec(buff, 0, 16, "AES");
        keys[1] = new SecretKeySpec(buff, 0, 24, "AES");
        keys[2] = new SecretKeySpec(buff, 0, 32, "AES");

        final List<TestThread> threads = new ArrayList<>();
        for (int x = 0; x < threadCount; x++) {
            final List<SecretKey> keyList = new ArrayList<>(3);
            while (keyList.isEmpty()) {
                for (int k = 0; k < keys.length; k++) {
                    if (rng.nextBoolean()) {
                        keyList.add(keys[k]);
                    }
                }
            }
            threads.add(new TestThread("AesCipherThread-" + x, rng, iterations, keyList));
        }

        // Start the threads
        for (final TestThread t : threads) {
            t.start();
        }

        // Wait and collect the results
        final List<Throwable> results = new ArrayList<>();
        for (final TestThread t : threads) {
            t.join();
            if (t.result != null) {
                results.add(t.result);
            }
        }
        if (!results.isEmpty()) {
            final AssertionError ex = new AssertionError("Throwable while testing threads");
            for (Throwable t : results) {
                t.printStackTrace();
                ex.addSuppressed(t);
            }
            throw ex;
        }
    }

    private static class TestThread extends Thread {
        private final SecureRandom rnd_;
        private final List<SecretKey> keys_;
        private final Cipher enc_;
        private final Cipher dec_;
        private final int iterations_;
        private final byte[] plaintext_;
        public volatile Throwable result = null;

        public TestThread(String name, SecureRandom rng, int iterations, List<SecretKey> keys)
                throws GeneralSecurityException {
            super(name);
            iterations_ = iterations;
            keys_ = keys;
            enc_ = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
            dec_ = Cipher.getInstance(ALGO_NAME, PROVIDER_AMAZON);
            plaintext_ = new byte[64];
            rnd_ = SecureRandom.getInstance("SHA1PRNG");
            byte[] seed = new byte[20];
            rng.nextBytes(seed);
            rnd_.setSeed(seed);
            rnd_.nextBytes(plaintext_);
        }

        @Override
        public void run() {
            for (int x = 0; x < iterations_; x++) {
                try {
                    final SecretKey key = keys_.get(rnd_.nextInt(keys_.size()));
                    final byte[] iv = TestUtil.getRandomBytes(12);
                    final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                    enc_.init(Cipher.ENCRYPT_MODE, key, spec);
                    dec_.init(Cipher.DECRYPT_MODE, key, spec);
                    assertArrayEquals(plaintext_, dec_.doFinal(enc_.doFinal(plaintext_)));
                } catch (final Throwable ex) {
                    result = ex;
                    return;
                }
            }
        }
    }
}
