# Important Differences
The [JCA/JCE](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html) specification does not completely define all behaviors of a given provider.
Although the Amazon Corretto Crypto Provider (ACCP) is fully compliant with the JCE, its behavior differs from the behavior of the default Java providers in several ways.
The following list of behavioral differences is not exhaustive, but is intended to capture the most important differences.

Despite these differences, ACCP remains a drop-in replacement for the vast majority of Java applications and doesn't change the application behavior, other than improving its performance.

# Behavior Changes
These differences are those most likely to be noticed by a consuming application. You might need to make minor changes to accommodate them.

## SignatureException
The official documentation does not fully specify when the [Signature](https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html) object is expected to throw a [SignatureException](https://docs.oracle.com/javase/8/docs/api/java/security/SignatureException.html).
Having multiple different ways to reject a signature (such as `signature.verify() == false` and throwing a `SignatureException`) is an anti-pattern and we should try to avoid it.
ACCP throws a `SignatureException` from `Signature.verify()` only when not throwing would introduce compatibility issues (such as with the [JCK](https://en.wikipedia.org/wiki/Technology_Compatibility_Kit#TCK_for_the_Java_platform).)
Currently, ACCP will throw a `SignatureException` only when verifying an EDSA signature that is not properly encoded.
In all other cases, ACCP will return `false` from `Signature.verify()` when given an invalid signature.
This is different from the default OpenJDK implementation, which also inspects the inner structure of RSA signatures and rejects them with a `SignatureException` if they are improperly encoded.
ACCP follows the guidance provided in [PKCS #1 section 8.2.2](https://tools.ietf.org/html/rfc8017#section-8.2.2) in that it does not parse the inner structure but, instead, does a binary comparison against the expected value.

For this reason, regardless of whether you use ACCP or not, we recommend the following structure for signature verification:
```java
    Signature signatureObject = Signature.getInstance(SIGNATURE_ALGORITHM);
    signatureObject.initVerify(publicKey);
    signatureObject.update(messageToVerify);
    boolean signatureValid = false;
    try {
        signatureValid = signatureObject.verify(signature);
    } catch (final SignatureException ex) {
        signatureValid = false;
    }
```

## Elliptic Curve KeyPairGeneration by curve size
Neither the JCE nor the default OpenJDK provider for Elliptic Curve Cryptography (SunEC) specify the effect of calling `KeyPairGenerator.initialize(int keysize)` with an arbitrary value.
This behavior is fully specified only for values of 192, 224, 256, 384, and 521.
This means that applications cannot depend on receiving a specific curve for any other value. Also, the application might encounter compatibility issues if SunEC ever changes its behavior or if the application changes to a different JCE provider.
In ACCP (after version 1.5.0), the `KeyPairGenerator.initialize(int keysize)` method fails with an `InvalidParameterException` for `keysize` values other than 192, 224, 256, 384, and 521.

For this reason, even if you don't use ACCP, we recommend that you use only the [KeyPairGenerator.initialize(AlgorithmParameterSpec params)](https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html#initialize-java.security.spec.AlgorithmParameterSpec-) method with an [ECGenParameterSpec](https://docs.oracle.com/javase/8/docs/api/java/security/spec/ECGenParameterSpec.html) to generate EC keys.
This construction is safe for all known JCE providers and is expected to remain safe even if the behavior of a provider changes.

For more information, see the [changelog](./CHANGELOG.md) notes for version 1.5.0.

## Cipher.getOutputSize() for AES-GCM
ACCP might overestimate the amount of space needed when encrypted with `AES/GCM/NoPadding` on versions prior to 1.6.0.
While this is compliant with the JCE (which [permits overestimation](https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html#getOutputSize-int-)) it has caused confusion for some developers.


## SecureRandom is never deterministic
Some implementation of `SecureRandom` (such as `SHA1PRNG`, provided by the default OpenJDK cryptographic providers) can operate deterministically if `SecureRandom.setSeed(byte[])` is called prior to any other methods.
This behavior allows for insecure seeding and might make the application less secure if it requires the `SecureRandom` instance to provide secure entropy (such as for cryptographic use).
The `SecureRandom` implementation provided by ACCP automatically seeds itself upon creation and cannot be used in a deterministic manner.
This change is relevant only to systems that need deterministic behavior based on a seed, such as in some simulations.
Systems that need deterministic behavior should not use an ACCP implementation of `SecureRandom`. They should select an implementation/algorithm that specifically meets their needs.

## SecureRandom uses thread local state internally
To avoid the costs of both RNG initialization and thread contention, ACCP maintains a single internal instance of SecureRandom for each thread.
Any time an instance of `SecureRandom` is used, ACCP routes the requests to the appropriate backing instance for the calling thread.
Because the output of calls to `SecureRandom` is computationally indistinguishable from actual random data, this implementation detail has no impact on callers other than improving performance.

## RSASSA-PSS Signature parameters may not be updated in-flight
To prevent callers from corrupting their signatures, we forbid them from updating a Signature's PSSParameterSpec while they are still updating a Signature object. Once the Signature has been updated, it must be reset, `sign()`'d, or `verify`'d before the PSS parameters may be updated. If a caller attempts to call `Signature.setParameter(...)` while a Signature instance has buffered data, we will throw an `IllegalStateException`.

# Extensions
Applications are unlikely to directly encounter any of these changes but may choose to take advantage of them.

## AES-GCM supports IvParameterSpec
ACCP allows use of [IvParameterSpec](https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/IvParameterSpec.html) when calling [Cipher.init()](https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html#init-int-java.security.Key-java.security.spec.AlgorithmParameterSpec-).
This is equivalent to using a [GCMParameterSpec](https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/GCMParameterSpec.html) with the same IV value and a tag length of 128 bits.
By supporting the same ParameterSpec as other ciphers (such as `AES/CBC/PKCS5Padding`, which should not be used as it is no longer secure), ACCP makes it easier to migrate to the secure choice of `AES/GCM/NoPadding`.
(This behavior is identical to how [BouncyCastle](https://bouncycastle.org/java.html) treats `IvParameterSpec` when used with AES-GCM.)

## AES-KWP restricted support for IvParameterSpec

While JCE allows for callers to [explicitly specify alternate IV values in AES KWP](https://github.com/corretto/corretto-17/blob/4922f0805033d2f4a872add164f05320ef1592d3/src/java.base/share/classes/com/sun/crypto/provider/KeyWrapCipher.java#L637-L639), AWS-LC does not, so neither does ACCP. AWS-LC is responseible for determing the value of the AIV as described [here in RFC 5649](ACCP restricts KWP's IV to the constant 4-byte value described [here](https://datatracker.ietf.org/doc/html/rfc5649#section-3).

## KeyAgreement supports reuse without reinitialization
ACCP permits reuse of a [KeyAgreement](https://docs.oracle.com/javase/8/docs/api/javax/crypto/KeyAgreement.html) object without calling `.init()` more than once.
This results in better performance for Static-Ephemeral key agreement protocols.

## AES is supported as a target key type for all KeyAgreement algorithms and supports an explicit size
[KeyAgreement.generateSecret(String)](https://docs.oracle.com/javase/8/docs/api/javax/crypto/KeyAgreement.html#generateSecret-java.lang.String-) can be called with an input of "AES" for all Key Agreement algorithms.
(The default Java implementation does not support "AES" as input with "ECDH" key agreement.)
If "AES" is passed to this method, ACCP returns the largest possible AES key corresponding to the agreed secret.
Alternatively, you can request an AES key of a particular size by appending the size (in bits) surrounded by brackets to this string.
(Ex: "AES[128]" or "AES[256]")
This returns a key of the requested strength or an `InvalidKeyException` if the agreed secret is not long enough for the requested AES key length.
(This method of specifying key size is identical to the way [BouncyCastle](https://bouncycastle.org/java.html) specifies key size for `KeyAgreement.generateSecret(String)`.)
