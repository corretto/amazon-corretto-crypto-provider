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
    private static final String TEMP_DIR_PREFIX = "amazonCorrettoCryptoProviderNativeLibraries.";
    private static final String JNI_LIBRARY_NAME = "amazonCorrettoCryptoProvider";
    private static final String LIBCRYPTO_NAME = "crypto";
    private static final String[] JAR_RESOURCES = {JNI_LIBRARY_NAME, LIBCRYPTO_NAME};
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
     * Indicates that libcrypto reports we are in a FIPS mode.
     */
    static final boolean FIPS_BUILD;

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
                // System.loadLibrary() can deadlock. Calling this explicitly should prevent
                // the problem from happening, but since we don't know what other threads are
                // doing, we cannot promise success.
                FileSystems.getDefault();
                tryLoadLibrary();
                return true;
            });
        } catch (final Throwable t) {
            available = false;
            error = t;
        }
        PROVIDER_VERSION_STR = versionStr;
        PROVIDER_VERSION = oldVersion;
        FIPS_BUILD = available && isFipsMode();

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

    private static void tryLoadLibraryFromJar() throws IOException {
        Path privateTempDirectory = createPrivateTmpDir(TEMP_DIR_PREFIX);

        for (String jarResource: JAR_RESOURCES) {
            String resourceFileName = System.mapLibraryName(jarResource);
            writeJarResourceToTemporaryFile(privateTempDirectory, resourceFileName);
        }

        /**
         * Java will internally call dlopen() on libamazonCorrettoCryptoProvider from within this System.load() call.
         * This will cause the runtime dynamic loader to load ACCP's shared library into a new LOCAL object group that
         * is a child of the current Java LOCAL object group. Any shared library dependencies of the library being
         * loaded (such as libcrypto) will also be loaded recursively into the same LOCAL object group until all
         * transitive shared library dependencies are loaded. The system's regular dynamic loading rules are followed
         * (namely, any RPATH values present will be used). Since libamazonCorrettoCryptoProvider is built with an RPATH
         * value of "$ORIGIN", the runtime dynamic loader will always look in the same directory as libACCP for any
         * shared library dependencies BEFORE attempting to look in any system directories containing potentially
         * conflicting libraries with the same name.
         *
         * This means at runtime the Java process's object group hierarchy would look like this:
         *
         *             +------------------------------------------------------------+
         *             |Group #0: GLOBAL Object Group                               |
         *             | - Usually empty unless using LD_PRELOAD or dlopen() with   |
         *             |   RTLD_GLOBAL                                              |
         *             |                                                            |
         *             +------------------------------------------------------------+
         *                                          ^
         *                                          |
         *                                          |
         *             +------------------------------------------------------------+
         *             |Group #1: LOCAL Object Group                                |
         *             | - Java and JVM Symbols (libjli), libc, ld-linux, etc       |
         *             |                                                            |
         *             +------------------------------------------------------------+
         *                      ^                                        ^
         *                      |                                        |
         *                      |                                        |
         *   +---------------------------------------+   +---------------------------------------+
         *   |Group #2: LOCAL Object Group           |   |Group #3: LOCAL Object Group           |
         *   | - libamazonCorrettoCryptoProvider,    |   | - Any other JNI libraries. (Eg with   |
         *   |   libcrypto                           |   |   potentially different libcrypto)    |
         *   |                                       |   |                                       |
         *   +---------------------------------------+   +---------------------------------------+
         *
         * Any shared libraries that are not present in Java's LOCAL object group (Group #1), will be loaded into a
         * new child LOCAL object group, lower in the object group hierarchy. This can be done multiple times for
         * multiple different JNI libraries. Note that since both Groups #2 and #3 have Group #1 as a parent, their
         * library symbols will not conflict with each another since each group only see's symbols from their own
         * parents in the hierarchy above them. This means it is possible for multiple different JNI libraries to be
         * loaded at runtime that use different libcrypto implementations so long as those JNI libraries configure
         * their RPath values correctly, and are compatible with any libraries that have already been loaded above
         * them in the hierarchy.
         *
         * Once a LOCAL object group is created and the recursive library loading is complete, that LOCAL object group
         * can no longer be modified at runtime other than to be deleted entirely with dlclose(). Subsequent
         * System.load() or dlopen(..., RTLD_LOCAL) calls will only create new child LOCAL Object Groups below the
         * current object group in the hierarchy, and will only load in shared libraries that are not present in the
         * caller's object group's hierarchy.
         *
         * Links:
         *  - https://docs.oracle.com/cd/E19957-01/806-0641/6j9vuquj2/index.html
         *  - http://people.redhat.com/drepper/dsohowto.pdf
         *  - https://docs.oracle.com/cd/E23824_01/pdf/819-0690.pdf
         *  - https://man7.org/linux/man-pages/man3/dlopen.3.html
         */
        Path accpJniSharedLibraryPath = privateTempDirectory.resolve(System.mapLibraryName(JNI_LIBRARY_NAME)).toAbsolutePath();
        System.load(accpJniSharedLibraryPath.toString());

        // If loading library from JAR file, then the compile-time and run-time libcrypto versions should be an exact match.
        validateLibcryptoExactVersionMatch();

        maybeDeletePrivateTempDir(privateTempDirectory);
    }


    private static void tryLoadLibraryFromSystem() {
        /**
         * Attempt to load library using system's default shared library lookup paths
         */
        System.loadLibrary(JNI_LIBRARY_NAME);
    }

    private static void tryLoadLibrary() throws Exception {
        // First, try to find the library in our own jar
        final boolean useExternalLib = Boolean.parseBoolean(getProperty("useExternalLib", "false"));
        boolean successfullyLoadedLibrary = false;
        Exception loadingException = null;

        if (!useExternalLib) {
            try {
                tryLoadLibraryFromJar();
                successfullyLoadedLibrary = true;
            } catch (Exception e) {
                loadingException = e;
            }
        }

        if (!successfullyLoadedLibrary) {
            // We failed to load the library from our JAR but don't know why.
            // Try to load it directly off of the system path.
            if (loadingException == null) {
                loadingException = new RuntimeCryptoException("Skipping bundled library due to system property");
            }
            try {
                tryLoadLibraryFromSystem();
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
     * Validates that the LibCrypto available at runtime is exactly the same as what was available at compile time.
     * This should only be done if loading ACCP from a JAR file, since if loading from system libraries then minor
     * version upgrades to libcrypto may cause breakages.
     */
    private static native boolean validateLibcryptoExactVersionMatch();
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

    private static void maybeDelete(final Path path) {
        if (!DebugFlag.PRESERVE_NATIVE_LIBRARIES.isEnabled()) {
            try {
                Files.delete(path);
            } catch (IOException ex) {
                LOG.warning("Unable to delete native library: " + ex);
            }
        }
    }

    private static void maybeDeletePrivateTempDir(final Path tmpDirectory) {
        for (String jarResource: JAR_RESOURCES) {
            String resourceFileName = System.mapLibraryName(jarResource);
            maybeDelete(tmpDirectory.resolve(resourceFileName));
        }
        maybeDelete(tmpDirectory);
    }

    private static Path writeJarResourceToTemporaryFile(Path tempDirectory, final String resourceFileName) throws IOException {
        final Path tempResourceFilePath = tempDirectory.resolve(resourceFileName);

        try (InputStream is = Loader.class.getResourceAsStream(resourceFileName);
             OutputStream os = Files.newOutputStream(tempResourceFilePath, StandardOpenOption.CREATE,
                     StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            final byte[] buffer = new byte[16 * 1024];
            int read = is.read(buffer);
            while (read >= 0) {
                os.write(buffer, 0, read);
                read = is.read(buffer);
            }
            os.flush();
        }

        // Ensure we delete any temp files on exit
        tempResourceFilePath.toFile().deleteOnExit();
        return tempResourceFilePath;
    }

    /**
     * We need a source of entropy to create a random temporary directory name at startup before we've loaded native
     * crypto libraries. So, for now, we just read from /dev/urandom. Clearly this won't work when we start supporting
     * Windows systems. We are intentionally taking as few dependencies here as possible.
     */
    private static byte[] bootstrapRng(int numBytes) throws IOException {
        final Path urandomPath = Paths.get("/dev/urandom");
        if (!Files.exists(urandomPath)) {
            throw new AssertionError("/dev/urandom must exist for bootstrapping");
        }

        final byte[] rndBytes = new byte[numBytes]; // Default java tmp files use this much entropy
        final int RETRY_LIMIT = 10;
        try (InputStream rndStream = Files.newInputStream(urandomPath, StandardOpenOption.READ)) {
            int attempt = 0;
            // We keep doing this until we can create something new or fail badly
            while (attempt < RETRY_LIMIT) {
                attempt++;
                if (rndStream.read(rndBytes) == rndBytes.length) {
                    return rndBytes;
                }
            }
        }
        throw new AssertionError("Unable to read enough entropy");
    }

    /**
     * Unfortunately, we cannot actually use Files.createTempFile, because that internally depends on
     * SecureRandom, which results in a circular dependency.
     */
    private static synchronized Path createPrivateTmpDir(final String prefix) throws IOException {
        final Path systemTempDir = Paths.get(System.getProperty("java.io.tmpdir"));
        if (!Files.isDirectory(systemTempDir)) {
            throw new AssertionError("java.io.tmpdir is not valid: " + systemTempDir);
        }

        final FileAttribute<Set<PosixFilePermission>> permissions =
                PosixFilePermissions.asFileAttribute(new HashSet<>(Arrays.asList(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE
        )));

        final byte[] rndBytes = bootstrapRng(Long.BYTES); // Default java tmp files use this much entropy
        final StringBuilder privateTempDir = new StringBuilder(prefix);

        for (byte b : rndBytes) {
            // We convert to an unsigned integer first to avoid sign-bit extension when converting to hex.
            String hexByte = Integer.toHexString(Byte.toUnsignedInt(b));
            if (hexByte.length() == 1) {
                privateTempDir.append('0');
            }
            privateTempDir.append(hexByte);
        }

        final Path privateDirFullPath = systemTempDir.resolve(privateTempDir.toString());
        final int RETRY_LIMIT = 10;
        int attempt = 0;

        while(attempt < RETRY_LIMIT) {
            attempt++;
            try {
                final Path result = Files.createDirectory(privateDirFullPath, permissions);
                if (DebugFlag.VERBOSELOGS.isEnabled()) {
                    LOG.log(Level.FINE, "Created temporary library directory");
                }
                result.toFile().deleteOnExit();
                return result;
            } catch (final FileAlreadyExistsException ex) {
                // We ignore and retry this exception
            } catch (final Exception ex) {
                // Any other exception is bad and we may need to quash.
                throw new AssertionError("Unable to create temporary directory");
            }
        }

        throw new AssertionError("Unable to create temporary directory. Retries exceeded.");
    }
}
