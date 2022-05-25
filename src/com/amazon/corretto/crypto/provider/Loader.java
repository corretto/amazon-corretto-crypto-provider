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

/**
 * This class owns <em>all</em> logic necessary for loading the native library.
 * For this reason it must not depend on any other classes from this project (other than Janitor).
 *
 * The rough logic flow is as follows:
 * <ol>
 * <li>Read library version from embedded properties file
 * <li>Use some entropy from {@code /dev/urandom} to create a random temporary filename
 * <li>Copy the shared object from within our own JAR to the temporary file
 * <li>Load the shared object as a library from the temporary file
 * <li>Delete the temporary file
 * <li>If loading the library from above fails, try to load the library from our standard library path
 * <li>If we have successfully loaded a library, ask it for the version it was compiled with
 * <li>If the versions match, we mark that we loaded successful, else, we record the error.
 * </ol>
 */
final class Loader {
    static final String PROPERTY_BASE = "com.amazon.corretto.crypto.provider.";
    private static final String LIBRARY_NAME = "amazonCorrettoCryptoProvider";
    private static final String LIBCRYPTO_NAME = "crypto";
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
     * Indicates that this build uses the FIPS build of accp
     */
    static final boolean FIPS_BUILD;
    /**
     * Indicates that libcrypto reports we are in a FIPS mode.
     */
    static final boolean FIPS_BUILD_NATIVE;

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
        boolean fipsBuild = false;

        try {
            versionStr = AccessController.doPrivileged((PrivilegedExceptionAction<String>) () -> {
                try (InputStream is = Loader.class.getResourceAsStream("version.properties")) {
                    Properties p = new Properties();
                    p.load(is);
                    return p.getProperty("versionStr");
                }
            });
            fipsBuild = AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) () -> {
                try (InputStream is = Loader.class.getResourceAsStream("version.properties")) {
                    Properties p = new Properties();
                    p.load(is);
                    return "ON".equalsIgnoreCase(p.getProperty("fipsBuild", "OFF"));
                }
            });

            Matcher m = OLD_VERSION_PATTERN.matcher(versionStr);
            if (!m.matches()) {
                throw new AssertionError("Version string has wrong form: " + versionStr);
            }
            oldVersion = Double.parseDouble(m.group(1));

            final boolean finalFipsBuild = fipsBuild;
            available = AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) () -> {
                // This is to work a JVM runtime bug where FileSystems.getDefault() and
                // System.loadLibrary() can deadlock. Calling this explicitly shoulf prevent
                // the problem from happening, but since we don't know what other threads are
                // doing, we cannot promise success.
                FileSystems.getDefault();

                // In a FIPS build we need to load a dynamic library of libcrypto first
                if (finalFipsBuild) {
                    final Path libCryptoPath = writeResourceToTemporaryFile(System.mapLibraryName(LIBCRYPTO_NAME));
                    tryLoadLibrary("accpLcLoader");
                    // Yes, this next bit is horribly evil but we need a way to lock such that it really is global to
                    // everything running in the JVM even if multiple classloaders have loaded multiple copies of this
                    // same class.
                    // We intentionally have nothing in this synchronized block except for a single method call.
                    boolean loadCompleted = false;
                    final String pathAsString = libCryptoPath.toAbsolutePath().toString();
                    synchronized (ClassLoader.getSystemClassLoader()) {
                        loadCompleted = loadLibCrypto(pathAsString);
                    }
                    maybeDelete(libCryptoPath);
                    if (!loadCompleted) {
                        LOG.info("Already loaded libcrypto");
                    }
                }
                tryLoadLibrary(LIBRARY_NAME);
                return true;
            });
        } catch (final Throwable t) {
            available = false;
            error = t;
        }
        PROVIDER_VERSION_STR = versionStr;
        PROVIDER_VERSION = oldVersion;
        FIPS_BUILD = fipsBuild;
        FIPS_BUILD_NATIVE = isFipsMode();

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
        if (DebugFlag.VERBOSELOGS.isEnabled()) {
            if (available) {
                LOG.log(Level.CONFIG, "Successfully loaded native library version " + PROVIDER_VERSION_STR);
            } else {
                LOG.log(Level.CONFIG, "Unable to load native library", error);
            }
        }

        // Finally start up a cleaning thread if necessary
        RESOURCE_JANITOR = new Janitor();
    }

    private static void maybeDelete(final Path path) {
        if (!DebugFlag.PRESERVE_NATIVE_LIBRARIES.isEnabled()) {
            try {
                Files.delete(path);
            } catch (IOException ex) {
                LOG.warning("Unable to delete native library: " + ex);
            }
        }
    }

    private static Path writeResourceToTemporaryFile(final String resourceName) throws IOException {
        final int index = resourceName.lastIndexOf('.');
        final String prefix = resourceName.substring(0, index);
        final String suffix = resourceName.substring(index, resourceName.length());

        final Path libPath = createTmpFile(prefix, suffix);

        try (InputStream is = Loader.class.getResourceAsStream(resourceName);
                OutputStream os = Files.newOutputStream(libPath, StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            final byte[] buffer = new byte[16 * 1024];
            int read = is.read(buffer);
            while (read >= 0) {
                os.write(buffer, 0, read);
                read = is.read(buffer);
            }
            os.flush();
        }
        return libPath;
    }

    private static void tryLoadLibrary(final String libraryName) throws Exception {
        // First, try to find the library in our own jar
        final boolean useExternalLib = Boolean.valueOf(getProperty("useExternalLib", "false"));
        Exception loadingException = null;

        if (useExternalLib) {
            loadingException = new RuntimeCryptoException("Skipping bundled library due to system property");
        } else if (libraryName != null) {
            final Path libPath = writeResourceToTemporaryFile(System.mapLibraryName(libraryName));
            try {
                System.load(libPath.toAbsolutePath().toString());
            } catch (final Exception ex) {
                loadingException = ex;
            } finally {
                maybeDelete(libPath);
            }
        } else {
            loadingException = new RuntimeCryptoException("Skipping bundled library null mapped name");
        }

        if (loadingException != null) {
            // We failed to load the library from our JAR but don't know why.
            // Try to load it directly off of the system path.
            try {
                System.loadLibrary(libraryName);
                return;
            } catch (final Throwable suppressedError) {
                loadingException.addSuppressed(suppressedError);
                throw loadingException;
            }
        }
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
     * Attempts to load (mangled) lib crypto from the specified path.
     * @param libraryPath the absolute path to load the library or
     * @return true if the library was loaded
     */
    private static native boolean loadLibCrypto(String libraryPath);
    /**
     * Indicates if libcrypto is a FIPS build or not.
     * Equivalent to {@code FIPS_mode() == 1}
     *
     * @return {@code true} iff the underlying libcrypto is a FIPS build.
     */
    private static native boolean isFipsMode();

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
    private static synchronized Path createTmpFile(final String prefix, final String suffix) throws IOException {
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
                    if (DebugFlag.VERBOSELOGS.isEnabled()) {
                        LOG.log(Level.FINE, "Created temporary library file after " + attempt + " attempts");
                    }
                    result.toFile().deleteOnExit();
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
