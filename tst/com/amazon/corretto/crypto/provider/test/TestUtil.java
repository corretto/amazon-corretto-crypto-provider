// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assumptions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

@SuppressWarnings("unchecked")
public class TestUtil {
    public static final String RESOURCE_REFLECTION = "REFLECTIVE_TOOLS";
    public static final String RESOURCE_PROVIDER = "JCE_PROVIDER";
    /**
     * Pseudo-resource used by ACCP tests to enforce that certain tests run by themselves.
     * All tests should takea "READ" lock on this resource.
     * Tests which require exclusive control should take a "READ_WRITE" lock.
     */
    public static final String RESOURCE_GLOBAL = "GLOBAL_TEST_LOCK";
    public static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
    public static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;

    /**
     * Thread local instances of SecureRandom with no further guarantees about implementation or security.
     *
     * These are only used for testing purposes and are configured specifically for speed rather than security.
     */
    public static final ThreadLocal<SecureRandom> MISC_SECURE_RANDOM = ThreadLocal.withInitial(
            () -> {
                try {
                    // We need something non-blocking and very fast which doesn't depend on our own implementation.
                    return SecureRandom.getInstance("SHA1PRNG");
                } catch (final NoSuchAlgorithmException ex) {
                    throw new AssertionError(ex);
                }
            });

    private static final File TEST_DIR = new File(System.getProperty("test.data.dir", "."));

    public static byte[] getRandomBytes(int length) {
        final byte[] result = new byte[length];
        MISC_SECURE_RANDOM.get().nextBytes(result);
        return result;
    }

    public static void assertArraysHexEquals(byte[] expected, byte[] actual) {
        final String expectedHex = Hex.encodeHexString(expected);
        final String actualHex = Hex.encodeHexString(actual);
        assertEquals(expectedHex, actualHex);
    }

    public static void assertThrows(Class<? extends Throwable> expected, ThrowingRunnable callable) {
        try {
            callable.run();
        } catch (Throwable t) {
            if (expected.isAssignableFrom(t.getClass())) {
                return;
            }

            throw new AssertionError("Unexpected exception: " + t, t);
        }

        fail("Expected " + expected);
    }

    public static void assertThrows(Class<? extends Throwable> expected, String expectedMessage, ThrowingRunnable callable) {
        try {
            callable.run();
        } catch (Throwable t) {
            if (expected.isAssignableFrom(t.getClass()) &&
                  t.getMessage().equals(expectedMessage)) {
                return;
            }

            throw new AssertionError("Unexpected exception: " + t, t);
        }

        fail("Expected " + expected);
    }

    // We need to access some package-private methods to verify that we perform proper bounds checks, etc, without
    // help from the JCE builtin Cipher classes. Unfortunately, the test classes cannot live in the same package as
    // the signed JAR, so we need to use reflection to cross the package boundary here.
    public static void disableByteBufferReflection() {
        try {
            Class<?> klass = Class.forName(
                    "com.amazon.corretto.crypto.provider.ReflectiveTools");
            Method m = klass.getDeclaredMethod("disableByteBufferReflection");
            m.setAccessible(true);

            m.invoke(null);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    public static void enableByteBufferReflection() {
        try {
            Class<?> klass = Class.forName(
                    "com.amazon.corretto.crypto.provider.ReflectiveTools");
            Method m = klass.getDeclaredMethod("enableByteBufferReflection");
            m.setAccessible(true);

            m.invoke(null);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    public static int sneakyInvoke_int(Object o, String methodName, Object... args) throws Throwable {
        return (Integer)sneakyInvoke(o, methodName, args);
    }

    public static <T> T sneakyInvoke(Object o, String methodName, Object... args) throws Throwable {
        Class<?> klass;
        Object receiver;

        if (o instanceof Class) {
            klass = (Class<?>)o;
            receiver = null;
        } else {
            klass = o.getClass();
            receiver = o;
        }

        return sneakyInvokeExplicit(klass, methodName, receiver, args);
    }

    public static <T> T sneakyInvokeExplicit(
            Class<?> klass, final String methodName, final Object receiver, final Object... args
    ) throws Throwable {
        while (klass != null) {
            for (Method m : klass.getDeclaredMethods()) {
                if (!m.getName().equals(methodName)) continue;

                if (argsCompatible(m.getParameterTypes(), args)) {
                    try {
                        m.setAccessible(true);
                        return (T)m.invoke(receiver, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                }
            }
            klass = klass.getSuperclass();
        }
        throw new Error("Can't find match for method");
    }

    public static Object sneakyConstruct(String className, Object... args) throws Throwable {
        final Class<?> klass = Class.forName(className);
        for (final Constructor<?> c : klass.getDeclaredConstructors()) {
            if (argsCompatible(c.getParameterTypes(), args)) {
                try {
                    c.setAccessible(true);
                    return c.newInstance(args);
                } catch (InvocationTargetException ex) {
                    throw ex.getCause();
                }
            }
        }
        throw new Error("Can't find match for method");
    }

    public static InputStream sneakyGetTestData(String fileName) {
        try {
            Class<?> klass = Class.forName(
                "com.amazon.corretto.crypto.provider.Loader");
            return (InputStream) sneakyInvoke(klass, "getTestData", fileName);
        } catch (Throwable e) {
            throw new Error(e);
        }
    }

    public static boolean argsCompatible(final Class<?>[] parameterTypes, final Object[] args) {
        if (parameterTypes.length != args.length) {
            return false;
        }

        boolean argsMatch = true;
        for (int i = 0; i < parameterTypes.length && argsMatch; i++) {
            Class<?> parameterType = parameterTypes[i];
            if (args[i] == null) {
                argsMatch = !parameterType.isPrimitive();
                continue;
            }

            Class<?> argsType = args[i].getClass();
            if (parameterType.isPrimitive() && argsType.getPackage().getName().equals("java.lang")) {
                // See if the corresponding boxed type is passed in

                try {
                    Field f = argsType.getField("TYPE");
                    if (f.get(null) == parameterType) continue;
                } catch (Exception e) {
                    // nope, fall through to the isAssignableFrom check
                }
            }

            if (!parameterType.isAssignableFrom(argsType)) {
                argsMatch = false;
                break;
            }
        }
        return argsMatch;
    }

    public static byte[] arrayOf(final byte b, final int len) {
        final byte[] result = new byte[len];
        Arrays.fill(result, b);
        return result;
    }
    
    public static byte[] decodeHex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Input length must be even");
        }
        byte[] result = new byte[hex.length() / 2];
        for (int x = 0; x < hex.length() / 2; x++) {
            result[x] = (byte) Integer.parseInt(hex.substring(2 * x, 2 * x + 2), 16);
        }
        return result;
    }

    public static InputStream getTestData(final String fileName) throws IOException {
        return new FileInputStream(new File(TEST_DIR, fileName));
    }

    public static Object sneakyGetField(final Object object, final String fieldName) {
        Field field;
        Object instance;

        if (object instanceof Class) {
            instance = null;
            field = findField(fieldName, (Class<?>)object);
        } else {
            instance = object;
            field = findField(fieldName, object.getClass());
        }

        field.setAccessible(true);

        try {
            return field.get(instance);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public static Class<?> sneakyGetInternalClass(final Class<?> parent, final String name) throws ClassNotFoundException {
      for (Class<?> clazz : parent.getDeclaredClasses()){
        if (clazz.getSimpleName().equals(name)) {
          return clazz;
        }
      }
      throw new ClassNotFoundException(String.format("No inner class %s of %s found", name, parent));
    }

    private static Field findField(final String fieldName, Class<?> klass) {
        Field field = null;
        while (true) {
            try {
                field = klass.getDeclaredField(fieldName);
                break;
            } catch (NoSuchFieldException e) {
                // proceed to superclass
                klass = klass.getSuperclass();
                if (klass == null) {
                    throw new IllegalArgumentException("Couldn't find field " + fieldName);
                }
            }
        }
        return field;
    }


    public static int versionCompare(String a, Provider provider) {
        return versionCompare(a, getProviderVersion(provider));
    }

    public static int versionCompare(String a, String b) {
        final String[] aParts = a.split("\\.");
        final String[] bParts = b.split("\\.");
        final int limit = Math.min(aParts.length, bParts.length);
        for (int x = 0; x < limit; x++) {
            int tmp = Integer.compare(Integer.parseInt(aParts[x]), Integer.parseInt(bParts[x]));
            if (tmp != 0) {
                return tmp;
            }
        }
        return Integer.compare(aParts.length, bParts.length);
    }

    private static String getProviderVersion(Provider provider) {
        try {
            return (String) sneakyInvoke(provider, "getVersionStr");
        } catch (final Throwable e) {
            return Double.toString(provider.getVersion());
        }
    }

    public static void assumeMinimumVersion(String minVersion, Provider provider) {
        String providerVersion = getProviderVersion(provider);
        Assumptions.assumeTrue(versionCompare(minVersion, providerVersion) <= 0,
                String.format("Required version %s, Actual version %s", minVersion, providerVersion));
    }

    public synchronized static Provider[] saveProviders() {
        return Security.getProviders();
    }

    public synchronized static void restoreProviders(final Provider[] providers) {
        if (Arrays.equals(providers, Security.getProviders())) {
            return;
        }
        for (Provider oldProvider : Security.getProviders()) {
            Security.removeProvider(oldProvider.getName());
        }
        for (Provider provider : providers) {
            Security.addProvider(provider);
        }
    }
}
