// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;

abstract class EvpSignatureBase extends SignatureSpi {
  // Package visible so main Provider can use it
  static final String P1363_FORMAT_SUFFIX = "inP1363Format";
  protected static final int RSA_PKCS1_PADDING = 1;
  protected static final int RSA_PKCS1_PSS_PADDING = 6;
  protected final AmazonCorrettoCryptoProvider provider_;
  protected final EvpKeyType keyType_;
  protected int paddingType_;
  protected Key untranslatedKey_ = null;
  protected EvpKey key_ = null;
  protected boolean signMode;
  protected int keyUsageCount_ = 0;
  protected String algorithmName_ = null;
  protected PSSParameterSpec pssParams_ = null;
  // While digest_ isn't needed for the all instances of this abstract class, it's cleaner to manage
  // it with the
  // rest of the signature parameter values.
  protected long digest_ = 0; // Must be kept in sync with pssParams_ or main algorithm name.
  protected long pssMgfMd_ = 0; // Must be kept in sync with pssParams_
  protected int pssSaltLen_ = 0; // Must be kept in sync with pssParams_

  EvpSignatureBase(
      final AmazonCorrettoCryptoProvider provider,
      final EvpKeyType keyType,
      final int paddingType,
      final long digest) {
    provider_ = provider;
    keyType_ = keyType;
    paddingType_ = paddingType;
    if (paddingType_ == RSA_PKCS1_PSS_PADDING) {
      internalSetParams(PSSParameterSpec.DEFAULT);
      // digest_ is set by internalSetParameters
    } else {
      internalSetParams(null);
      // Overwrite the 0 set by internalSetParameters
      digest_ = digest;
    }
  }

  /**
   * Internal utility function to ensure that when we set a new parameter spec we properly parse it
   * and keep all other extract values in sync.
   */
  protected void internalSetParams(final PSSParameterSpec params) {
    if (params == null) {
      pssParams_ = null;
      digest_ = 0;
      pssMgfMd_ = 0;
      pssSaltLen_ = 0;
    } else {
      pssParams_ = params;
      digest_ = Utils.getMdPtr(params.getDigestAlgorithm());
      pssMgfMd_ =
          Utils.getMdPtr(((MGF1ParameterSpec) params.getMGFParameters()).getDigestAlgorithm());
      pssSaltLen_ = params.getSaltLength();
    }
  }

  protected abstract void engineReset();

  // Called reflectively upon creation
  void setAlgorithmName(String algorithmName) {
    this.algorithmName_ = algorithmName;
  }

  /**
   * Destroys the native context.
   *
   * @param ctx native context
   */
  private static native void destroyContext(long ctx);

  @Override
  protected synchronized void engineInitSign(final PrivateKey privateKey)
      throws InvalidKeyException {
    if (privateKey == null) {
      throw new InvalidKeyException("Key must not be null");
    }

    if (untranslatedKey_ != privateKey) {
      if (!keyType_.jceName.equalsIgnoreCase(privateKey.getAlgorithm())
          && !privateKey.getAlgorithm().startsWith(keyType_.jceName)) {
        throw new InvalidKeyException(
            String.format(
                "Invalid algorithm: %s, expected %s", privateKey.getAlgorithm(), keyType_.jceName));
      }
      keyUsageCount_ = 0;
      untranslatedKey_ = privateKey;
      if (key_ != null) {
        key_.releaseEphemeral();
      }
      key_ = provider_.translateKey(untranslatedKey_, keyType_);
    }
    signMode = true;
    engineReset();
  }

  @Override
  protected synchronized void engineInitVerify(final PublicKey publicKey)
      throws InvalidKeyException {
    if (publicKey == null) {
      throw new InvalidKeyException("Key must not be null");
    }

    if (untranslatedKey_ != publicKey) {
      if (!keyType_.jceName.equalsIgnoreCase(publicKey.getAlgorithm())
          && !publicKey.getAlgorithm().startsWith(keyType_.jceName)) {
        throw new InvalidKeyException();
      }
      keyUsageCount_ = 0;
      untranslatedKey_ = publicKey;
      if (key_ != null) {
        key_.releaseEphemeral();
      }
      key_ = provider_.translateKey(untranslatedKey_, keyType_);
    }
    signMode = false;
    engineReset();
  }

  @Override
  @Deprecated
  protected Object engineGetParameter(final String param) throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  @Override
  @Deprecated
  protected void engineSetParameter(final String param, final Object value)
      throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  @Override
  protected synchronized void engineSetParameter(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (params instanceof PSSParameterSpec) {
      final PSSParameterSpec pssParams = (PSSParameterSpec) params;
      if (keyType_ != EvpKeyType.RSA || paddingType_ != RSA_PKCS1_PSS_PADDING) {
        throw new InvalidAlgorithmParameterException(
            "PSS params only supported for RSASSA-PSS signatures");
      }
      if (!isBufferEmpty()) {
        throw new IllegalStateException(
            "Cannot update PSS parameters with buffered data, reset Signature.");
      }
      if (!"MGF1".equals(pssParams.getMGFAlgorithm())) {
        throw new InvalidAlgorithmParameterException("Invalid PSS MGF algorithm");
      }
      // 1 is currently the only supported trailer field:
      //
      // >  trailerField is the trailer field number, for compatibility with
      // >  the draft IEEE P1363a [27].  It shall be 1 for this version of the
      // >  document, which represents the trailer field with hexadecimal
      // >  value 0xbc.  Other trailer fields (including the trailer field
      // >  HashID || 0xcc in IEEE P1363a) are not supported in this document
      //
      // https://datatracker.ietf.org/doc/html/rfc3447#appendix-A.2.3
      if (pssParams.getTrailerField() != PSSParameterSpec.DEFAULT.getTrailerField()) {
        // NOTE: PSSParameterSpec throws IllegalArgumentException instead of
        // InvalidAlgorithmParameterException
        //       so we match that behavior here.
        throw new IllegalArgumentException("Invalid PSS trailer field");
      }
      if (pssParams.getMGFParameters() == null) {
        throw new InvalidAlgorithmParameterException("PSS parameters must specify MGF1 parameters");
      }
      // Cache MD struct ptrs, validate digest names and salt len, update params
      try {
        Utils.getMdPtr(pssParams.getDigestAlgorithm());
        Utils.getMdPtr(((MGF1ParameterSpec) pssParams.getMGFParameters()).getDigestAlgorithm());
      } catch (Exception e) {
        throw new InvalidAlgorithmParameterException();
      }
      // RFC 3447 does not specify an explicit max or min on salt lengh,
      // but does constrain it relative to other parameters:
      //
      // > If emLen < hLen + sLen + 2, output "encoding error" and stop.
      //
      // https://datatracker.ietf.org/doc/html/rfc3447#section-9.1.1
      //
      // Additionally, AWS-LC reserves negative salt lengths:
      // https://github.com/awslabs/aws-lc/blob/main/crypto/fipsmodule/rsa/padding.c#L649-L662
      final int saltLen = pssParams.getSaltLength();
      final int mdLen = Utils.getMdLen(Utils.getMdPtr(pssParams.getDigestAlgorithm()));
      // If key is not yet set, assume it has a 2048-bit modulus. Even if a smaller key ends up
      // being
      // used, AWS-LC will detect this and throw an error here:
      // https://github.com/awslabs/aws-lc/blob/main/crypto/fipsmodule/rsa/padding.c#L661
      final int emLen =
          key_ != null ? (((RSAKey) key_).getModulus().bitLength() + 7) / 8 : 2048 / 8;
      if (saltLen < 0 || saltLen > emLen - mdLen - 2) {
        // NOTE: PSSParameterSpec throws IllegalArgumentException instead of
        // InvalidAlgorithmParameterException
        //       so we match that behavior here.
        throw new IllegalArgumentException("PSS salt length invalid");
      }
      internalSetParams(pssParams);
    } else if (params instanceof ECParameterSpec) {
      // Some applications set the EC Parameters for ECDSA algorithms.
      // This doesn't change behavior, but we need to ensure it is correct.
      if (keyType_ != EvpKeyType.EC) {
        throw new InvalidAlgorithmParameterException("ECParameterSpec only supported with EC keys");
      }
      final ECParameterSpec expectedParams = ((ECKey) key_).getParams();
      if (!EcUtils.ecParameterSpecsAreEqual(expectedParams, (ECParameterSpec) params)) {
        throw new InvalidAlgorithmParameterException("Algorithm parameters do not match key");
      }
      // Check passes, no actual changes needed
    } else {
      throw new InvalidAlgorithmParameterException(
          "Specified parameters supported by this algorithm");
    }
  }

  protected abstract boolean isBufferEmpty();

  @Override
  protected synchronized AlgorithmParameters engineGetParameters() {
    if (paddingType_ == RSA_PKCS1_PSS_PADDING && pssParams_ != null) {
      try {
        final AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS");
        params.init(pssParams_);
        return params;
      } catch (final NoSuchAlgorithmException ex) {
        // NOTE: this method can only throw unchecked exceptions, and UnsupportedOperationException
        // seems like the most appropriate for JDK platforms that don't support RSASSA-PSS.
        throw new UnsupportedOperationException("RSASSA-PSS unsupported.", ex);
      } catch (final GeneralSecurityException ex) {
        throw new AssertionError(ex);
      }
    }
    return null;
  }

  /**
   * Ensures that we are properly initialized for the current mode of operation if specified.
   *
   * @param mode {@code true} if we're trying to sign data and {@code false} if we are trying to
   *     verify. If this value is {@code null} then it does not check to ensure it is initialized
   *     for a specific mode.
   * @throws SignatureException if we are not properly initialized
   */
  protected void ensureInitialized(final Boolean mode) throws SignatureException {
    // Code coverage is low as the java.security.Signature object actually
    // detects these cases before it reaches us.
    if (key_ == null) {
      throw new SignatureException("Not initialized");
    }
    if (mode != null && mode.booleanValue() != signMode) {
      throw new SignatureException("Incorrect mode for operation");
    }
  }

  protected static final class EvpContext extends NativeResource {
    protected EvpContext(final long ptr) {
      super(ptr, EvpSignatureBase::destroyContext);
    }
  }

  /**
   * Converts and returns the modified signature to verify <em>only if necessary</em> and returns
   * {@code null} otherwise. If {@code null} is returned then the passed in parameters should be
   * used for later verification. Otherwise, the entire returned array should be used. This method
   * has a somewhat odd API since we want to avoid unnecessary array copies/allocations and it is an
   * internal API anyway.
   *
   * @return the converted signature or {@code null} if no conversion is necessary
   * @throws SignatureException if the signature is badly malformed
   */
  protected byte[] maybeConvertSignatureToVerify(byte[] signature, int offset, int length)
      throws SignatureException {
    if (algorithmName_ != null && algorithmName_.endsWith(P1363_FORMAT_SUFFIX)) {
      final ECKey ecKey = (ECKey) key_;
      final int numLen = (ecKey.getParams().getOrder().bitLength() + 7) / 8;
      return ieeeP1363toAsn1(signature, offset, length, numLen);
    } else {
      return null;
    }
  }

  /**
   * Determines if we need to convert the signature <em>we generated</em> and performs said
   * conversion. <em>This methods may throw {@link AssertionError} on invalid input so should only
   * be given trusted inputs.</em>.
   */
  protected byte[] maybeConvertSignatureToReturn(byte[] signature) throws SignatureException {
    if (algorithmName_ != null && algorithmName_.endsWith(P1363_FORMAT_SUFFIX)) {
      final ECKey ecKey = (ECKey) key_;
      final int numLen = (ecKey.getParams().getOrder().bitLength() + 7) / 8;
      return asn1ToiIeeeP1363(signature, numLen);
    } else {
      return signature;
    }
  }

  /**
   * This is a trivial conversion from two equal-length concatenated integers to an ASN.1 sequence.
   *
   * <p>Since the resulting structure is so simple, we do not need a full ASN.1 engine and can cover
   * all cases by hand.
   */
  protected static byte[] ieeeP1363toAsn1(
      byte[] signature, final int offset, final int length, int numLen) throws SignatureException {
    if (2 * numLen != length) {
      throw new SignatureException();
    }

    // This is the easiest way to trim unneeded zero-bytes
    final byte[] r =
        (new BigInteger(1, Arrays.copyOfRange(signature, offset, offset + numLen))).toByteArray();
    final byte[] s =
        (new BigInteger(1, Arrays.copyOfRange(signature, offset + numLen, offset + 2 * numLen)))
            .toByteArray();

    if (r.length > 127 || s.length > 127) {
      throw new SignatureException("R or S value is too large");
    }

    // Encode the total sequence length. This might be one or two bytes
    final int seqLength = r.length + s.length + 4;
    final byte[] encodedSeqLength;
    if (seqLength <= 127) {
      encodedSeqLength = new byte[] {(byte) (seqLength & 0xFF)};
    } else if (seqLength <= 256) {
      encodedSeqLength = new byte[] {(byte) 0x81, (byte) (seqLength & 0xFF)};
    } else {
      throw new SignatureException("R or S value is too large");
    }

    final byte[] result = new byte[1 + encodedSeqLength.length + seqLength];
    int position = 0;
    result[position++] = 0x30; // SEQUENCE
    System.arraycopy(encodedSeqLength, 0, result, position, encodedSeqLength.length);
    position += encodedSeqLength.length;
    result[position++] = 0x02; // INTEGER
    result[position++] = (byte) (r.length & 0xFF); // Length of R
    System.arraycopy(r, 0, result, position, r.length);
    position += r.length;
    result[position++] = 0x02; // INTEGER
    result[position++] = (byte) (s.length & 0xFF); // Length of S
    System.arraycopy(s, 0, result, position, s.length);
    position += s.length;
    if (position != result.length) {
      throw new AssertionError(
          "Final position of " + position + " does not match expected value of " + result.length);
    }

    return result;
  }

  /** Note: This should only be used on trusted inputs * */
  protected static byte[] asn1ToiIeeeP1363(byte[] signature, int numLen) throws SignatureException {
    // Check the ASN.1 for correctness and extract offsets
    int position = 0;
    if (signature[position++] != 0x30) {
      throw new AssertionError();
    }

    // Length may be one or two bytes
    int seqLen = Byte.toUnsignedInt(signature[position++]);
    if (seqLen == 0x81) {
      // Two byte length with second byte being the length
      seqLen = Byte.toUnsignedInt(signature[position++]);
    } else if (seqLen > 127) {
      // Unhandled long, reserved, or indefinite length
      throw new AssertionError();
    }
    if (seqLen != signature.length - position) {
      throw new AssertionError();
    }

    final int rOffset = position;
    if (signature[rOffset] != 0x02) {
      throw new AssertionError();
    }
    int rLen = Byte.toUnsignedInt(signature[rOffset + 1]);
    int rStart = rOffset + 2;

    final int sOffset = rStart + rLen;
    if (signature[sOffset] != 0x02) {
      throw new AssertionError(
          Base64.getEncoder().encodeToString(signature)
              + " : "
              + String.format(
                  "%x, %x, %x",
                  signature[sOffset - 1], signature[sOffset], signature[sOffset + 1]));
    }
    int sLen = Byte.toUnsignedInt(signature[sOffset + 1]);
    int sStart = sOffset + 2;

    // Remove leading zero bytes
    if (signature[rStart] == 0) {
      rStart++;
      rLen--;
    }
    if (signature[sStart] == 0) {
      sStart++;
      sLen--;
    }

    byte[] result = new byte[numLen * 2];
    System.arraycopy(signature, rStart, result, numLen - rLen, rLen);
    System.arraycopy(signature, sStart, result, numLen + numLen - sLen, sLen);
    return result;
  }

  /**
   * Does an initial check of the signature seeing if it is of the proper format and size. This lets
   * us quickly reject invalid signatures in a way that the JDK expects.
   */
  protected void sniffTest(final byte[] signature, final int offset, final int length)
      throws SignatureException {
    // Right now we only check RSA signatures to ensure they are the proper length
    if (key_ instanceof RSAKey) {
      final RSAKey rsaKey = (RSAKey) key_;
      final int expectedLength = (rsaKey.getModulus().bitLength() + 7) / 8;
      if (length != expectedLength) {
        throw new SignatureException("RSA Signature of invalid length. Expected " + expectedLength);
      }
    }
  }
}
