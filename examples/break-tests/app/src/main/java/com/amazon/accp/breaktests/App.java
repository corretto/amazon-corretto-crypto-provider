package com.amazon.accp.breaktests;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

public class App {

    public static void main(String[] args) throws Exception {
        if (System.getenv("BREAK_TESTS_WITH_GDB") == null) {
            breakingTestsWithAwsLcHooks();
        } else {
            breakingTestsWithGdb();
        }
    }

    private static void breakingTestsWithAwsLcHooks() throws Exception {
        final AmazonCorrettoCryptoProvider p = AmazonCorrettoCryptoProvider.INSTANCE;
        System.out.println("Possible values for BORINGSSL_FIPS_BREAK_TEST are {\"ECDSA_PWCT\", \"RSA_PWCT\", \"CRNG\"}");
        System.out.println("To see the effect of BORINGSSL_FIPS_BREAK_TEST, build ACCP with hooks to allow failure:");
        System.out.println("    ./gradlew clean -DALLOW_FIPS_TEST_BREAK=true -DFIPS=true build");
        System.out.println("==================================================================");
        final String boringsslFipsBreakTestEnvVar = System.getenv("BORINGSSL_FIPS_BREAK_TEST");
        if (boringsslFipsBreakTestEnvVar != null) {
            System.out.println("BORINGSSL_FIPS_BREAK_TEST is set to " + boringsslFipsBreakTestEnvVar);
        } else {
            System.out.println("BORINGSSL_FIPS_BREAK_TEST is not defined");
        }

        System.out.println("Checking if ACCP is installed properly. If not, we'll get an exception ...");
        p.assertHealthy();
        System.out.println("Checking if ACCP FIPS is good ... " + p.isFips());

        final KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", p);
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        System.out.println("'ecKpg.generateKeyPair().getPrivate().getFormat()' would throw an exception when");
        System.out.println("BORINGSSL_FIPS_BREAK_TEST is set to ECDSA_PWCT:");
        System.out.println("    BORINGSSL_FIPS_BREAK_TEST=ECDSA_PWCT ./gradlew run");
        System.out.println(ecKpg.generateKeyPair().getPrivate().getFormat());
    }

    private static void breakingTestsWithGdb() throws Exception {
        final AmazonCorrettoCryptoProvider p = AmazonCorrettoCryptoProvider.INSTANCE;
        System.out.println("Using GDB to break tests ...");
        System.out.println("Checking if ACCP is installed properly. If not, we'll get an exception ...");
        p.assertHealthy();
        System.out.println("Checking if ACCP FIPS is good ... " + p.isFips());
        System.out.println("Now, use GDB and attach to this process...");
        System.out.println("The process id is " + ProcessHandle.current().pid());
        System.out.println("Use \'gdb -p " + ProcessHandle.current().pid() + "\' to attach to the process");
        System.out.println("Let's find where libcrypto.so is loaded. Run the following command in gdb console ...");
        System.out.println("    (gdb) info proc mappings");
        System.out.println("Use the bounds in the following command and look for a pattern:");
        System.out.println("    (gdb) find /b START_ADDRESS, END_ADDRESS, 0xa6, 0x90, 0x1f, 0x97, 0xbe");
        System.out.println("The about put of the above command would like the following:");
        System.out.println("    1 pattern found");
        System.out.println("    0x7f7f52c1dc0e");
        System.out.println("Zero that address...");
        System.out.println("   (gdb) set {int}0x7f7f52c1dc0e = 0x0");
        System.out.println("Exit gdb session");
        System.out.println("Once your done, press any key to continue ...");
        final BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        br.readLine();
        System.out.println("Checking if ACCP FIPS is still good ... " + p.isFips());
    }
}
