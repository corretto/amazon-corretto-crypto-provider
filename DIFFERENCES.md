# Important Differences
The [JCA/JCE](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html) specification does not completely define all behaviors by a given provider.
Thus, though the Amazon Corretto Crypto Provider (ACCP) is fully compliant with the JCE, it does differ in behavior from the default Java providers in several ways.
The following list is not exhaustive but is intended to capture the most important differences to our consumers.
As any other differences are noticed or introduced, we will add them to this list.

Despite the presence of these differences, ACCP remains a drop-in replacement for the vast majority of Java applications and will result in no behavior differences other than improved performance.

# Behavior Changes
These differences are those most likely to be noticed by a consuming application and may require development effort to work around.

## SignatureException
The official documentation does not fully specify when the [Signature](https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html) object is expected to throw a [SignatureException](https://docs.oracle.com/javase/8/docs/api/java/security/SignatureException.html).
Having multiple different ways to reject a signature (such as `signature.verify() == false` and throwing a `SignatureException`) is an anti-pattern and we should try to avoid it.
ACCP tries to never throw a `SignatureException` from `Signature.verify()` except when not doing so would introduce too many compatibility issues (such as with the [JCK](https://en.wikipedia.org/wiki/Technology_Compatibility_Kit#TCK_for_the_Java_platform).)
Currently, ACCP will only throw a `SignatureException` when verifying an EDSA or DSA signature which is not properly encoded.
In all other cases, ACCP will just return `false` from `Signature.verify()` when given an invalid signature.
This is different from the default OpenJDK implementation which will also inspect the inner structure of RSA signatures to reject them with a `SignatureException` if they are improperly encoded.
ACCP follows the guidance provided in [PKCS #1 section 8.2.2](https://tools.ietf.org/html/rfc8017#section-8.2.2) in that it does not parse the inner structure but instead does a binary comparison against the expected value.

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
Neither the JCE nor the default OpenJDK provider for Elliptic Curve Cryptography (SunEC) specify behavior for when `KeyPairGenerator.initialize(int keysize)` is called with an arbitrary value.
Behavior is only fully specified for the values of 192, 224, 256, 384, and 521.
This means that applications cannot depend on receiving a specific curve for any other value and may encounter compatibility issues should SunEC ever change its behavior or the application changes to a different JCE provider.
ACCP removes this unspecified behavior by rejecting use of this method for all values not on the above list (for any ACCP version after 1.5.0) with an `InvalidParameterException`.

For this reason, regardless of whether you use ACCP or not, we recommend that you only use the [KeyPairGenerator.initialize(AlgorithmParameterSpec params)](https://docs.oracle.com/javase/8/docs/api/java/security/KeyPairGenerator.html#initialize-java.security.spec.AlgorithmParameterSpec-) method with an [ECGenParameterSpec](https://docs.oracle.com/javase/8/docs/api/java/security/spec/ECGenParameterSpec.html) to generate EC keys.
This construction is safe for all known JCE providers and is expected to remain safe even should providers change behavior in other ways.

For more information, please see the [changelog](./CHANGELOG.md) notes for version 1.5.0.

## Cipher.getOutputSize() for AES-GCM
ACCP may overestimate the amount of space needed when encrypted with `AES/GCM/NoPadding`.
While this is compliant with the JCE (which [permits overestimation](https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html#getOutputSize-int-)) it has caused confusion for some developers.
We are tracking this as [issue #135](https://github.com/corretto/amazon-corretto-crypto-provider/issues/135) and will improve this behavior.

## SecureRandom is never deterministic
Some implementation of `SecureRandom` (such as `SHA1PRNG`, provided by the default OpenJDK cryptographic providers) can operate deterministically if `SecureRandom.setSeed(byte[])` is called prior to any other methods.
This behavior allows for insecure seeding and may result in lower security if the application requires the `SecureRandom` instance to provide secure entropy (such as for cryptographic use).
The `SecureRandom` implementation provided by ACCP automatically seeds itself upon creation and cannot be used in a deterministic manner.
This change is only relevant to systems which need deterministic behavior based on a seed such as some simulations.
Systems which need deterministic behavior should not use an ACCP implementation of `SecureRandom` and should select an implementation/algorithm which specifically meets their needs.

## SecureRandom uses thread local state internally
To avoid the costs of both RNG initialization and thread contention, ACCP maintains a single internal instance of SecureRandom for each thread.
Any time an instance of `SecureRandom` is used, ACCP will route the requests to the appropriate backing instance for the calling thread.
As the output of calls to `SecureRandom` is computationally indistinguishable from actual random data, this implementation detail has no impact on callers (other than improving performance).

# Extensions
Applications are unlikely to directly encounter any of these changes but may choose to take advantage of them.

## AES-GCM supports IvParameterSpec
ACCP allows use of [IvParameterSpec](https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/IvParameterSpec.html) when calling [Cipher.init()](https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html#init-int-java.security.Key-java.security.spec.AlgorithmParameterSpec-).
This is equivalent to using a [GCMParameterSpec](https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/GCMParameterSpec.html) with the same IV value and a tag length of 128 bits.
By supporting the same ParameterSpec as other ciphers (such as `AES/CBC/PKCS5Padding`, which should not be used as it is no longer secure), ACCP makes it easier to migrate to the secure choice of `AES/GCM/NoPadding`.
(This behavior is identical to how [BouncyCastle](https://bouncycastle.org/java.html) treats `IvParameterSpec` when used with AES-GCM.)

## KeyAgreement supports reuse without reinitialization
ACCP permits reuse of a [KeyAgreement](https://docs.oracle.com/javase/8/docs/api/javax/crypto/KeyAgreement.html) object without needing to call `.init()` more than once.
This gives better performance for Static-Ephemeral key agreement protocols.

## AES is supported as a target key type for all KeyAgreement algorithms and supports an explicit size
[KeyAgreement.generateSecret(String)](https://docs.oracle.com/javase/8/docs/api/javax/crypto/KeyAgreement.html#generateSecret-java.lang.String-) can be called with an input of "AES" for all Key Agreement algorithms.
(The default Java implementation does not support "AES" as input with "ECDH" key agreement.)
If the string "AES" is passed to this method then ACCP will return the largest possible AES key corresponding to the agreed secret.
Alternatively, an explicit AES key size can be requested by appending the size (in bits) surrounded by brackets to this string.
(Ex: "AES[128]" or "AES[256]")
This will always result in producing a key of the requested strength or an `InvalidKeyException` if the agreed secret is not sufficiently long for the requested AES key length.
(This method of specifying key size is identical to how [BouncyCastle](https://bouncycastle.org/java.html) does it with `KeyAgreement.generateSecret(String)`.)
