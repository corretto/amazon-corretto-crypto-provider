// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class Loader {
    private static final String PROPERTY_BASE = "com.amazon.corretto.crypto.provider.";
    private static final String LIBRARY_NAME = "amazonCorrettoCryptoProvider";
    private static final Pattern TEST_FILENAME_PATTERN = Pattern.compile("[-a-zA-Z0-9]+(\\.[a-zA-Z0-9]+)*");
    private static final Logger LOG = Logger.getLogger("AmazonCorrettoCryptoProvider");

    // Version strings live in the loader because we want to be able to access them before
    // any other parts of this library are touched and potentially (statically) loaded.
    private static final Pattern OLD_VERSION_PATTERN = Pattern.compile("(\\d+\\.\\d+)\\.\\d+");

    @Deprecated
    // Cannot be fully removed until we remove support for Java 8
    static final double PROVIDER_VERSION;
    static final String PROVIDER_VERSION_STR;

    /**
     * Returns an InputStream associated with {@code fileName} contained in the "testdata" subdirectory, relative
     * to the location of this class file within the jar/jmod.
     */
    static InputStream getTestData(String fileName) {
        if (!TEST_FILENAME_PATTERN.matcher(fileName).matches()) {
            throw new IllegalArgumentException("Invalid filename: " + fileName);
        }
        final InputStream result = AccessController.doPrivileged(
                (PrivilegedAction<InputStream>) () -> Loader.class.getResourceAsStream("testdata/" + fileName)
        );
        if (result == null) {
            throw new AssertionError("Unable to load test data from file testdata/" + fileName);
        }
        return result;
    }

    /**
     * Prepends {@link #PROPERTY_BASE} and then calls {@link System#getProperty(String)} in a privileged context.
     */
    static String getProperty(String propertyName) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(PROPERTY_BASE + propertyName)
        );
    }

    /**
     * Prepends {@link #PROPERTY_BASE} and then calls {@link System#getProperty(String, String)} in a privileged context.
     */
    static String getProperty(String propertyName, String def) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(PROPERTY_BASE + propertyName, def)
        );
    }

    static {
        boolean available = false;
        Throwable error = null;
        String versionStr = null;
        double oldVersion = 0;

        try {
            versionStr = AccessController.doPrivileged((PrivilegedExceptionAction<String>) () -> {
                try (InputStream is = Loader.class.getResourceAsStream("version.properties")) {
                    Properties p = new Properties();
                    p.load(is);
                    return p.getProperty("versionStr");
                }
            });

            Matcher m = OLD_VERSION_PATTERN.matcher(versionStr);
            if (!m.matches()) {
                throw new AssertionError("Version string has wrong form: " + versionStr);
            }
            oldVersion = Double.parseDouble(m.group(1));

            available = AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) () -> {
                // This is to work a JVM runtime bug where FileSystems.getDefault() and
                // System.loadLibrary() can deadlock. Calling this explicitly shoulf prevent
                // the problem from happening, but since we don't know what other threads are
                // doing, we cannot promise success.
                FileSystems.getDefault();

                // First, try to find the library in our own jar
                String libraryName = System.mapLibraryName(LIBRARY_NAME);
                if (libraryName != null) {
                    int index = libraryName.lastIndexOf('.');
                    final String prefix = libraryName.substring(0, index);
                    final String suffix = libraryName.substring(index, libraryName.length());

                    final Path libPath = createTmpFile(prefix, suffix);
                    try (final InputStream is = Loader.class.getResourceAsStream(libraryName);
                         final OutputStream os = Files.newOutputStream(libPath, StandardOpenOption.CREATE,
                                 StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                        final byte[] buffer = new byte[16 * 1024];
                        int read = is.read(buffer);
                        while (read >= 0) {
                            os.write(buffer, 0, read);
                            read = is.read(buffer);
                        }
                        os.flush();
                        System.load(libPath.toAbsolutePath().toString());
                        return true;
                    } catch (final Throwable realError) {
                        // We failed to load the library from our JAR but don't know why.
                        // Try to load it directly off of the system path.
                        try {
                            System.loadLibrary(LIBRARY_NAME);
                            return true;
                        } catch (final Throwable suppressedError) {
                            realError.addSuppressed(suppressedError);
                            throw realError;
                        }
                    } finally {
                        Files.delete(libPath);
                    }
                }

                return false;
            });
        } catch (final Throwable t) {
            available = false;
            error = t;
        }
        PROVIDER_VERSION_STR = versionStr;
        PROVIDER_VERSION = oldVersion;

        // Check for native/java library version mismatch
        if (available) {
            try {
                assertVersionMatch();
            } catch (final AssertionError e) {
                available = false;
                error = e;
            }
        }
        IS_AVAILABLE = available;
        LOADING_ERROR = error;
        if (available) {
            LOG.log(Level.CONFIG, "Successfully loaded native library version " + PROVIDER_VERSION_STR);
        } else {
            LOG.log(Level.CONFIG, "Unable to load native library", error);
        }

        // Finally start up a cleaning thread if necessary
        RESOURCE_JANITOR = new Janitor();
    }

    static final boolean IS_AVAILABLE;
    static final Throwable LOADING_ERROR;

    static final Janitor RESOURCE_JANITOR;

    static void load() {
        // no-op - but we run the static block as a side effect
    }

    static void checkNativeLibraryAvailability() {
        if (!IS_AVAILABLE) {
            throw new UnsupportedOperationException("Native library not available");
        }
    }

    private static native String getNativeLibraryVersion();

    /**
     * Throws an {@link AssertionError} if the java and native libraries do not match versions.
     */
    private static void assertVersionMatch() {
        final String nativeVersion;
        try {
            nativeVersion = getNativeLibraryVersion();
        } catch (final Throwable t) {
            throw new AssertionError(t);
        }

        if (!PROVIDER_VERSION_STR.equals(nativeVersion)) {
            throw new AssertionError(String.format(
                    "Library version mismatch. Java: %s, Native: %s",
                    PROVIDER_VERSION_STR, nativeVersion));
        }
    }

    /**
     * Unfortunately, we cannot actually use Files.createTempFile, because that internally depends on
     * SecureRandom, which results in a circular dependency. So, for now, we just read from
     * /dev/urandom. Clearly this won't work when we start supporting windows systems. We are intentionally taking
     * as few dependencies here as possible.
     */
    private synchronized static Path createTmpFile(final String prefix, final String suffix) throws IOException {
        final Path urandomPath = Paths.get("/dev/urandom");
        if (!Files.exists(urandomPath)) {
            throw new AssertionError("/dev/urandom must exist for bootstrapping");
        }
        final Path tmpDir = Paths.get(System.getProperty("java.io.tmpdir"));
        if (!Files.isDirectory(tmpDir)) {
            throw new AssertionError("java.io.tmpdir is not valid: " + tmpDir);
        }

        final FileAttribute<Set<PosixFilePermission>> permissions =
                PosixFilePermissions.asFileAttribute(new HashSet<>(Arrays.asList(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE
        )));

        final byte[] rndBytes = new byte[Long.BYTES]; // Default java tmp files use this much entropy
        final int RETRY_LIMIT = 1000;
        try (InputStream rndStream = Files.newInputStream(urandomPath, StandardOpenOption.READ)) {
            int attempt = 0;
            // We keep doing this until we can create something new or fail badly
            while (attempt < RETRY_LIMIT) {
                attempt++;
                if (rndStream.read(rndBytes) != rndBytes.length) {
                    throw new AssertionError("Unable to read enough entropy");
                }

                final StringBuilder fileName = new StringBuilder(prefix);
                for (byte b : rndBytes) {
                    // We convert to an unsigned integer first to avoid sign-bit extension when converting to hex.
                    String hexByte = Integer.toHexString(Byte.toUnsignedInt(b));
                    if (hexByte.length() == 1) {
                        fileName.append('0');
                    }
                    fileName.append(hexByte);
                }
                fileName.append(suffix);

                final Path tmpFile = tmpDir.resolve(fileName.toString());

                try {
                    final Path result = Files.createFile(tmpFile, permissions);
                    LOG.log(Level.FINE, "Created temporary library file after " + attempt + " attempts");
                    return result;
                } catch (final FileAlreadyExistsException ex) {
                    // We ignore and retry this exception
                } catch (final Exception ex) {
                    // Any other exception is bad and we may need to quash.
                    throw new AssertionError("Unable to create temporary file");
                }
            }
        }
        throw new AssertionError("Unable to create temporary file. Retries exceeded.");
    }
}
