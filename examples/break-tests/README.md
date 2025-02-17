# Breaking FIPS tests

## Using hooks from AWS-LC to break tests
AWS-LC provides some hooks that allow one to break FIPS tests. These hooks are only present if AWS-LC is
built with such support. ACCP allows such builds with `ALLOW_FIPS_TEST_BREAK` flag:
```bash
./gradlew clean -DALLOW_FIPS_TEST_BREAK=true -DFIPS=true build
```

Once ACCP is built this way, the value of the environment variable `BORINGSSL_FIPS_BREAK_TEST` controls
which tests can break. The possible values for `BORINGSSL_FIPS_BREAK_TEST`
are `{"ECDSA_PWCT", "RSA_PWCT", "CRNG"}`.

For example, use the following command to see failure of EC key pair generation:
```bash
BORINGSSL_FIPS_BREAK_TEST=ECDSA_PWCT ./gradlew run
```

## Using GDB to break tests

To break the tests using GDB, there is no need to build ACCP with special flags,
other than `-DFIPS=true`. Here are the step to break the tests:
1. Run the example with intention to use GDB:
```bash
BREAK_TESTS_WITH_GDB=1 ./gradlew run
```
2. In another terminal, use GDB and attach to this process. The prompt will let you know the process id.
3. Once attached, find where `libcrypto.so` is loaded. Use `(gdb) info proc mappings` for this purpose.
4. Use find command with the start and end address of where `libcrypto.so` is loaded to look for the following pattern of bytes: `0xa6, 0x90, 0x1f, 0x97, 0xbe`. This can be accomplished the following:
```bash
(gdb) find /b START_ADDRESS, END_ADDRESS, 0xa6, 0x90, 0x1f, 0x97, 0xbe
```
Ensure `START_ADDRESS` and `END_ADDRESS` are replaced with the values found in step 3.
5. The output of the above command is an address like `0x7f7f52c1dc0e`. Set this address to zero:
```bash
(gdb) set {int}0x7f7f52c1dc0e = 0x0
```
6. Quit GDB session and go back to the original terminal. Press any key to continue.
7. At this point you would see the failure and FIPS breakage.

The pattern `0xa6, 0x90, 0x1f, 0x97, 0xbe` is part of [a test in AWS-LC](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/self_check/self_check.c#L727-L730).
We are modifying the expected result of a test.