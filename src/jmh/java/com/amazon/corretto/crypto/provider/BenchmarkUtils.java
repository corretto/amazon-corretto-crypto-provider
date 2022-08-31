package com.amazon.corretto.crypto.provider;

import java.security.SecureRandom;
import java.security.Security;
import java.security.Provider;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

class BenchmarkUtils {
    private BenchmarkUtils() {}

    private static final SecureRandom sr = new SecureRandom();
    private static final Set<String> NON_DEFAULT_PROVIDERS = new HashSet(Arrays.asList("BC", "BCFIPS", "AmazonCorrettoCryptoProvider"));
    private static final Provider[] DEFAULT_PROVIDERS;
    static {
        DEFAULT_PROVIDERS = Security.getProviders();
        for (Provider provider : DEFAULT_PROVIDERS) {
            if (NON_DEFAULT_PROVIDERS.contains(provider.getName())) {
                throw new RuntimeException("Provider prematurely (statically) registered: " + provider);
            }
        }
    }

    static byte[] getRandBytes(int n) {
        byte[] ret = new byte[n];
        final int bcMaxSize = 32768;
        for (int ii = 0; ii < n; ii += bcMaxSize) {
            byte[] data = new byte[bcMaxSize];
            sr.nextBytes(data);
            System.arraycopy(data, 0, ret, ii, Math.min(bcMaxSize, n-ii));
        }
        return ret;
    }

    static void setupProvider(String providerName) {
        removeAllProviders();
        switch(providerName) {
            case "AmazonCorrettoCryptoProvider":
                installDefaultProviders();
                AmazonCorrettoCryptoProvider.install();
                AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
                break;
            case "BC":
                Security.insertProviderAt(new BouncyCastleProvider(), 1);
                break;
            case "SUN":
            case "SunEC":
            case "SunJCE":
            case "SunRsaSign":
                installDefaultProviders();
                break;
            default:
                throw new RuntimeException("Unrecognized provider: " + providerName);
        }
    }

    static void installDefaultProviders() {
        for (Provider provider : DEFAULT_PROVIDERS) {
            Security.addProvider(provider);
        }
    }

    static void removeAllProviders() {
        for (Provider provider : Security.getProviders()) {
            Security.removeProvider(provider.getName());
        }
    }
}
