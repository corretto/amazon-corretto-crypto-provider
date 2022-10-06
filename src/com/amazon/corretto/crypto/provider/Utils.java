// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.nio.ByteBuffer;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Miscellaneous utility methods.
 */
final class Utils {
    private static final String CACHE_SELF_TEST_RESULTS = "cacheselftestresults";
    private Utils() {
        // Prevent instantiation
    }
    static final byte[] EMPTY_ARRAY = new byte[0];
    private static final Logger LOG = Logger.getLogger("AmazonCorrettoCryptoProvider");

    private static final Map<String,Long> digestPtrByName = new ConcurrentHashMap<>();
    private static final Map<Long,Integer> digestLengthByPtr = new ConcurrentHashMap<>();

    /**
     * Returns the difference between the native pointers of a and b. That is, if overlap > 0, then
     * a.get(overlap) == b.get(0), and if overlap < 0, then b.get(-overlap) == a.get(0).
     *
     * If the buffers do not overlap, or if one of the arguments is not a direct byte buffer, returns a value greater
     * than Integer.MAX_VALUE.
     *
     * @param a
     * @param b
     * @return
     */
    static native long getNativeBufferOffset(ByteBuffer a, ByteBuffer b);

    /**
     * Returns the value of the EVP_MD* object corresponding with the named digest.
     * Corresponds to a call to @{code EVP_get_digestbyname}.
     */
    static native long getEvpMdFromName(String digestName);
    /**
     * Returns the output length for a digest in bytes specified by {@code evpMd}.
     */
    static native int getDigestLength(long evpMd);

    static String jceDigestNameToAwsLcName(final String jceName) {
        if (jceName == null) {
            return null;
        }
        // e.g. "SHA-512/256" => "SHA512-256"
        return jceName.replace("-", "").replace("/", "-").toUpperCase();
    }

    /**
     * Converts a hash name (according to JCE standards) to an {@code long} containing the value of the native
     * {@code EVP_MD*} pointer.
     * If {@code digestName == null} then this will return {@code 0}.
     * Otherwise this is guaranteed to return a non-zero value as it will throw {@link IllegalArgumentException}
     * if libcrypto cannot translate the name into a known {@code EVP_MD*} pointer.
     */
    static long getMdPtr(final String digestName) {
        if (digestName == null) {
            return 0;
        }
        final String name = jceDigestNameToAwsLcName(digestName);

        if (!name.startsWith("SHA")) {
            throw new IllegalArgumentException("Unsupported digest algorithm: " + digestName);
        }
        final long ptr = digestPtrByName.computeIfAbsent(name, Utils::getEvpMdFromName);
        if (ptr == 0) {
            throw new IllegalArgumentException("Unsupported digest algorith: " + digestName);
        }
        return ptr;
    }

    static int getMdLen(final long mdPtr) {
        return digestLengthByPtr.computeIfAbsent(mdPtr, Utils::getDigestLength);
    }

    /**
     * Returns false if the two bytebuffers given definitely don't overlap; true if they do overlap, or if we're unable
     * to determine whether they overlap. Unfortunately it's not possible to determine whether certain bytebuffers
     * overlap (notably, if one buffer is a RO buffer and the other is an array-backed buffer, we cannot check for
     * overlap without empirically modifying the array-backed buffer).
     *
     * Overlap is determined based on buffer position and limit.
     */
    static boolean buffersMaybeOverlap(ByteBuffer a, ByteBuffer b) {
        boolean directA = a.isDirect();
        boolean directB = b.isDirect();
        boolean arrayA = a.hasArray();
        boolean arrayB = b.hasArray();

        if ((directA || directB) && (directA != directB)) {
            // One is direct and the other isn't; there can be no overlap
            return false;
        }

        if (directA && directB) {
            // By slicing the buffers, we can avoid having to think about the native pointer and position(); the
            // position will simply be added into the native pointer.

            // This will also allow getNativeBufferOffset to fully determine whether the buffers overlap in native code,
            // by factoring the limit() into the buffer capacity.
            return getNativeBufferOffset(a.slice(), b.slice()) <= Integer.MAX_VALUE;
        }

        // At this point we'll need to check array() and arrayOffset(), but to do this we need both to hasArray().
        if (!(arrayA && arrayB)) {
            // One doesn't hasArray, so we're prevented from checking for overlap. Return true to assume overlap.
            return true;
        }

        if (a.array() != b.array()) {
            // different arrays, so no overlap
            return false;
        }

        // Same array, check for overlap within array
        long a_offset = (long)a.arrayOffset() + (long)a.position();
        long b_offset = (long)b.arrayOffset() + (long)b.position();

        if (a_offset > b_offset) {
            return b_offset + (long) b.limit() > a_offset;
        } else {
            return a_offset + (long) a.limit() > b_offset;
        }
    }

    /**
     * Returns true if a length-bytes region after offset o1 in a1 overlaps with a length-bytes region after offset
     * o2 in a2.
     */
    static boolean arraysOverlap(byte[] a1, int o1, byte[] a2, int o2, int length) {
        // We can't delegate to byffersMaybeOverlap directly as the length may be too long for one of the two input
        // arrays

        if (a1 != a2) return false;

        if (o1 > o2) {
            // swap the two arrays to simplify logic
            return arraysOverlap(a2, o2, a1, o1, length);
        }

        return (long)o1 + length > (long)o2;
    }

    static byte[] encodeForWrapping(final AmazonCorrettoCryptoProvider provider, final Key key) throws InvalidKeyException {
        try {
            final byte[] encoded;
            if (key instanceof SecretKey) {
                encoded = key.getEncoded();
            } else if (key instanceof PublicKey) {
                final KeyFactory factory = getKeyFactory(provider, key.getAlgorithm());
                encoded = factory.getKeySpec(key, X509EncodedKeySpec.class).getEncoded();
            } else if (key instanceof PrivateKey) {
                final KeyFactory factory = getKeyFactory(provider, key.getAlgorithm());
                encoded = factory.getKeySpec(key, PKCS8EncodedKeySpec.class).getEncoded();
            } else {
                throw new InvalidKeyException("Key does not implement SecretKey, PublicKey, or PrivateKey");
            }
            if (encoded == null || encoded.length == 0) {
                throw new InvalidKeyException("Could not obtain encoded key");
            }
            return encoded;
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException ex) {
            throw new InvalidKeyException("Wrapping failed", ex);
        }
    }

    static Key buildUnwrappedKey(final AmazonCorrettoCryptoProvider provider, final byte[] rawKey, final String algorithm, final int keyType)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        switch (keyType) {
            case Cipher.SECRET_KEY:
                return buildUnwrappedSecretKey(rawKey, algorithm);
            case Cipher.PUBLIC_KEY:
                return buildUnwrappedPublicKey(provider, rawKey, algorithm);
            case Cipher.PRIVATE_KEY:
                return buildUnwrappedPrivateKey(provider, rawKey, algorithm);
            default:
                throw new IllegalArgumentException("Unexpected key type: " + keyType);
        }
    }

    static SecretKey buildUnwrappedSecretKey(final byte[] rawKey, final String algorithm) {
        return new SecretKeySpec(rawKey, algorithm);
    }

    static PublicKey buildUnwrappedPublicKey(final AmazonCorrettoCryptoProvider provider, final byte[] rawKey, final String algorithm)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        final KeyFactory kf = getKeyFactory(provider, algorithm);
        return kf.generatePublic(new X509EncodedKeySpec(rawKey));
    }

    static PrivateKey buildUnwrappedPrivateKey(final AmazonCorrettoCryptoProvider provider, final byte[] rawKey, final String algorithm)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        final KeyFactory kf = getKeyFactory(provider, algorithm);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(rawKey));
    }

    static byte[] xor(final byte[] a, final byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("arrays must be the same length");
        }
        final byte[] result = new byte[a.length];
        for (int x = 0; x < a.length; x++) {
            result[x] = (byte) (a[x] ^ b[x]);
        }
        return result;
    }

    static byte[] decodeHex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Input length must be even");
        }
        byte[] result = new byte[hex.length() / 2];
        for (int x = 0; x < hex.length() / 2; x++) {
            result[x] = (byte) Integer.parseInt(hex.substring(2 * x, 2 * x + 2), 16);
        }
        return result;
    }

    private static void assertArrayEquals(String message, byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError("Arrays do not match: " + message);
        }
    }

    public static void testMac(Mac mac, SecretKey key, byte[] message, byte[] expected) throws GeneralSecurityException {
        mac.init(key);
        final int[] lengths = new int[] { 1, 3, 4, 7, 8, 16, 32, 48, 64, 128, 256 };
        final String alg = mac.getAlgorithm();
        assertArrayEquals(alg, expected, mac.doFinal(message));
        for (int x = 0; x < message.length; x++) {
            mac.update(message[x]);
        }
        assertArrayEquals(alg + "-Byte", expected, mac.doFinal());
        for (final int length : lengths) {
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                mac.update(message, x, len);
            }
            assertArrayEquals(alg + "-" + length, expected, mac.doFinal());
        }

        // Byte buffer wrapping
        mac.update(ByteBuffer.wrap(message));
        assertArrayEquals(alg + "-ByteBuffer-Wrap", expected, mac.doFinal());

        for (final int length : lengths) {
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                mac.update(ByteBuffer.wrap(message, x, len));
            }
            assertArrayEquals(alg + "-ByteBuffer-Wrap-" + length, expected, mac.doFinal());
        }

        // Byte buffer wrapping, read-only
        mac.update(ByteBuffer.wrap(message).asReadOnlyBuffer());
        assertArrayEquals(alg + "-ByteBuffer-Wrap-RO", expected, mac.doFinal());

        for (final int length : lengths) {
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                mac.update(ByteBuffer.wrap(message, x, len).asReadOnlyBuffer());
            }
            assertArrayEquals(alg + "-ByteBuffer-Wrap-RO-" + length, expected, mac.doFinal());
        }

        // Byte buffer non-direct
        ByteBuffer bbuff = ByteBuffer.allocate(message.length);
        bbuff.put(message);
        bbuff.flip();
        mac.update(bbuff);
        assertArrayEquals(alg + "-ByteBuffer-NonDirect", expected, mac.doFinal());

        for (final int length : lengths) {
            bbuff = ByteBuffer.allocate(length);
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                bbuff.clear();
                bbuff.put(message, x, len);
                bbuff.flip();
                mac.update(bbuff);
            }
            assertArrayEquals(alg + "-ByteBuffer-NonDirect-" + length, expected, mac.doFinal());
        }

        // Byte buffer direct
        bbuff = ByteBuffer.allocateDirect(message.length);
        bbuff.put(message);
        bbuff.flip();
        mac.update(bbuff);
        assertArrayEquals(alg + "-ByteBuffer-Direct", expected, mac.doFinal());

        for (final int length : lengths) {
            bbuff = ByteBuffer.allocateDirect(length);
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                bbuff.clear();
                bbuff.put(message, x, len);
                bbuff.flip();
                mac.update(bbuff);
            }
            assertArrayEquals(alg + "-ByteBuffer-Direct-" + length, expected, mac.doFinal());
        }

        // Byte buffer direct, read-only
        bbuff = ByteBuffer.allocateDirect(message.length);
        bbuff.put(message);
        bbuff.flip();
        mac.update(bbuff.asReadOnlyBuffer());
        assertArrayEquals(alg + "-ByteBuffer-Direct", expected, mac.doFinal());

        for (final int length : lengths) {
            bbuff = ByteBuffer.allocateDirect(length);
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                bbuff.clear();
                bbuff.put(message, x, len);
                bbuff.flip();
                mac.update(bbuff.asReadOnlyBuffer());
            }
            assertArrayEquals(alg + "-ByteBuffer-Direct-" + length, expected, mac.doFinal());
        }
    }

    public static void testDigest(MessageDigest md, byte[] message, byte[] expected) {
        final int[] lengths = new int[] { 1, 3, 4, 7, 8, 16, 32, 48, 64, 128, 256 };
        final String alg = md.getAlgorithm();
        assertArrayEquals(alg, expected, md.digest(message));
        for (int x = 0; x < message.length; x++) {
            md.update(message[x]);
        }
        assertArrayEquals(alg + "-Byte", expected, md.digest());
        for (final int length : lengths) {
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                md.update(message, x, len);
            }
            assertArrayEquals(alg + "-" + length, expected, md.digest());
        }

        // Byte buffer wrapping
        md.update(ByteBuffer.wrap(message));
        assertArrayEquals(alg + "-ByteBuffer-Wrap", expected, md.digest());

        for (final int length : lengths) {
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                md.update(ByteBuffer.wrap(message, x, len));
            }
            assertArrayEquals(alg + "-ByteBuffer-Wrap-" + length, expected, md.digest());
        }

        // Byte buffer wrapping, read-only
        md.update(ByteBuffer.wrap(message).asReadOnlyBuffer());
        assertArrayEquals(alg + "-ByteBuffer-Wrap-RO", expected, md.digest());

        for (final int length : lengths) {
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                md.update(ByteBuffer.wrap(message, x, len).asReadOnlyBuffer());
            }
            assertArrayEquals(alg + "-ByteBuffer-Wrap-RO-" + length, expected, md.digest());
        }

        // Byte buffer non-direct
        ByteBuffer bbuff = ByteBuffer.allocate(message.length);
        bbuff.put(message);
        bbuff.flip();
        md.update(bbuff);
        assertArrayEquals(alg + "-ByteBuffer-NonDirect", expected, md.digest());

        for (final int length : lengths) {
            bbuff = ByteBuffer.allocate(length);
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                bbuff.clear();
                bbuff.put(message, x, len);
                bbuff.flip();
                md.update(bbuff);
            }
            assertArrayEquals(alg + "-ByteBuffer-NonDirect-" + length, expected, md.digest());
        }

        // Byte buffer direct
        bbuff = ByteBuffer.allocateDirect(message.length);
        bbuff.put(message);
        bbuff.flip();
        md.update(bbuff);
        assertArrayEquals(alg + "-ByteBuffer-Direct", expected, md.digest());

        for (final int length : lengths) {
            bbuff = ByteBuffer.allocateDirect(length);
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                bbuff.clear();
                bbuff.put(message, x, len);
                bbuff.flip();
                md.update(bbuff);
            }
            assertArrayEquals(alg + "-ByteBuffer-Direct-" + length, expected, md.digest());
        }

        // Byte buffer direct, read-only
        bbuff = ByteBuffer.allocateDirect(message.length);
        bbuff.put(message);
        bbuff.flip();
        md.update(bbuff.asReadOnlyBuffer());
        assertArrayEquals(alg + "-ByteBuffer-Direct", expected, md.digest());

        for (final int length : lengths) {
            bbuff = ByteBuffer.allocateDirect(length);
            for (int x = 0; x < message.length; x += length) {
                final int len = x + length > message.length ? message.length - x : length;
                bbuff.clear();
                bbuff.put(message, x, len);
                bbuff.flip();
                md.update(bbuff.asReadOnlyBuffer());
            }
            assertArrayEquals(alg + "-ByteBuffer-Direct-" + length, expected, md.digest());
        }
    }

    /**
     * A byte buffer guaranteed to have nothing but zeros to allow for faster zerorization.
     */
    private static final ByteBuffer ZERO_BYTE_BUF = ByteBuffer.allocate(8192).asReadOnlyBuffer();

    /**
     * Clears (zeros) all data in the buffer. Disregards position and limit; the entire capacity of the buffer will be
     * erased.
     * @param buffer
     */
    static void zeroByteBuffer(ByteBuffer buffer) {
        buffer = buffer.duplicate();
        buffer.clear();

        while (buffer.hasRemaining()) {
            ByteBuffer src = ZERO_BYTE_BUF.duplicate();
            src.limit(Math.min(src.remaining(), buffer.remaining()));

            buffer.put(src);
        }
    }

    private static KeyFactory getKeyFactory(final AmazonCorrettoCryptoProvider provider, final String algorithm)
            throws NoSuchAlgorithmException {
        final EvpKeyType type = EvpKeyType.fromJceName(algorithm);
        if (type != null) {
            return provider.getKeyFactory(type);
        } else {
            return KeyFactory.getInstance(algorithm);
        }
    }

    static <E extends Enum<E>> void optionsFromProperty(
        final Class<E> clazz, final EnumSet<E> set, final String propertyName) {
        final String propertyValue = Loader.getProperty(propertyName, "");
        if (propertyValue.equalsIgnoreCase("help")) {
            System.err.format("Valid values for %s%s are: %s or ALL",
                Loader.PROPERTY_BASE, propertyName, EnumSet.allOf(clazz));
        }
        final String[] extraCheckOptions = propertyValue.split(",");
        for (final String check : extraCheckOptions) {
            if (check.equalsIgnoreCase("all")) {
                set.addAll(EnumSet.allOf(clazz));
                break;
            }
            try {
                final E value = Enum.valueOf(clazz, check.toUpperCase());
                if (value != null) {
                    set.add(value);
                }
            } catch (Exception ex) {
                // Ignore
            }
        }
    }

    private static int JAVA_VERSION = 0;
    static int getJavaVersion() {
        if (JAVA_VERSION > 0) {
            return JAVA_VERSION;
        }
        final String strVersion = AccessController.doPrivileged((PrivilegedAction<String>) () ->
            System.getProperty("java.specification.version")
        );
        try {
            final String[] parts = strVersion.split("\\.");
            if (parts[0].equals("1")) {
                JAVA_VERSION = Integer.parseInt(parts[1]);
            } else {
                JAVA_VERSION = Integer.parseInt(parts[0]);
            }
        } catch (final RuntimeException ex) {
            LOG.warning("Unable to parse version string: " + strVersion);
            JAVA_VERSION = 8; // fallback to something safe
        }
        return JAVA_VERSION;
    }

    static boolean getCacheSelfTestResultsProperty() {
        final String relyOnCacheSelfTestResultsStr = Loader.getProperty(CACHE_SELF_TEST_RESULTS, "true").toLowerCase();
        if (!relyOnCacheSelfTestResultsStr.equals("true") && !relyOnCacheSelfTestResultsStr.equals("false")) {
            System.err.format("Valid values for %s are false and true, with true as default", CACHE_SELF_TEST_RESULTS);
            return true;
        }
        return Boolean.parseBoolean(relyOnCacheSelfTestResultsStr);
    }
}

