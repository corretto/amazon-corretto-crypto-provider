// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Parameters for ACCP's {@code HPKE} Cipher and KeyPairGenerator: an RFC 9180 base-mode suite,
 * optional {@code info}, and the recipient's KEM encapsulation.
 *
 * <p>The supported suites have named constants with empty {@code info} and no encapsulation:
 *
 * <ul>
 *   <li>{@link #ML_KEM_768_HKDF_SHA256_AES_128_GCM}
 *   <li>{@link #ML_KEM_1024_HKDF_SHA384_AES_256_GCM}
 * </ul>
 *
 * <p>Suite support is checked when a Cipher or KeyPairGenerator is initialized and depends on the
 * linked AWS-LC. ACCP also accepts JDK 26's {@code javax.crypto.spec.HPKEParameterSpec} for
 * supported base-mode suites; PSK and auth modes are unsupported.
 *
 * <p>Instances are immutable, so the constants are safe to share. Byte arrays are copied on the way
 * in and on the way out.
 */
public final class HpkeParameterSpec implements AlgorithmParameterSpec {

  /** KEM id for ML-KEM-768 (draft-ietf-hpke-pq). */
  public static final int KEM_ML_KEM_768 = 0x0041;

  /** KEM id for ML-KEM-1024 (draft-ietf-hpke-pq). */
  public static final int KEM_ML_KEM_1024 = 0x0042;

  /** KDF id for HKDF-SHA256 (RFC 9180). */
  public static final int KDF_HKDF_SHA256 = 0x0001;

  /** KDF id for HKDF-SHA384 (RFC 9180). */
  public static final int KDF_HKDF_SHA384 = 0x0002;

  /** AEAD id for AES-128-GCM (RFC 9180). */
  public static final int AEAD_AES_128_GCM = 0x0001;

  /** AEAD id for AES-256-GCM (RFC 9180). */
  public static final int AEAD_AES_256_GCM = 0x0002;

  private static final String JDK_SPEC_CLASS = "javax.crypto.spec.HPKEParameterSpec";
  // Unknown public instance methods may represent fields the adapter would silently drop.
  private static final Set<String> KNOWN_JDK_SPEC_METHODS = new HashSet<>();

  static {
    KNOWN_JDK_SPEC_METHODS.addAll(
        Arrays.asList(
            "of",
            "withInfo",
            "withPsk",
            "withEncapsulation",
            "withAuthKey",
            "kem_id",
            "kdf_id",
            "aead_id",
            "info",
            "psk",
            "psk_id",
            "authKey",
            "encapsulation"));
    for (final Method m : Object.class.getMethods()) {
      KNOWN_JDK_SPEC_METHODS.add(m.getName());
    }
  }

  /** ML-KEM-768, HKDF-SHA256, AES-128-GCM; base mode, empty info. */
  public static final HpkeParameterSpec ML_KEM_768_HKDF_SHA256_AES_128_GCM =
      of(KEM_ML_KEM_768, KDF_HKDF_SHA256, AEAD_AES_128_GCM);

  /** ML-KEM-1024, HKDF-SHA384, AES-256-GCM (the CNSA 2.0 algorithms); base mode, empty info. */
  public static final HpkeParameterSpec ML_KEM_1024_HKDF_SHA384_AES_256_GCM =
      of(KEM_ML_KEM_1024, KDF_HKDF_SHA384, AEAD_AES_256_GCM);

  private final int kemId;
  private final int kdfId;
  private final int aeadId;
  private final byte[] info;
  private final byte[] encapsulation;

  private HpkeParameterSpec(
      final int kemId,
      final int kdfId,
      final int aeadId,
      final byte[] info,
      final byte[] encapsulation) {
    this.kemId = kemId;
    this.kdfId = kdfId;
    this.aeadId = aeadId;
    this.info = info;
    this.encapsulation = encapsulation;
  }

  /**
   * Creates a spec for the suite named by the three ids, with empty {@code info} and no
   * encapsulation. Whether ACCP supports the suite is checked at initialization, not here.
   *
   * @param kem_id the KEM id
   * @param kdf_id the KDF id
   * @param aead_id the AEAD id
   * @return the base-mode suite parameters
   * @throws IllegalArgumentException if any id is outside {@code [0, 65535]}
   */
  public static HpkeParameterSpec of(final int kem_id, final int kdf_id, final int aead_id) {
    return create(kem_id, kdf_id, aead_id, null, null);
  }

  /**
   * Copies {@code info} and {@code encapsulation}; unlike {@link #withInfo}, accepts an empty
   * {@code info}. A null {@code info} means empty; a null {@code encapsulation} means none.
   */
  private static HpkeParameterSpec create(
      final int kemId,
      final int kdfId,
      final int aeadId,
      final byte[] info,
      final byte[] encapsulation) {
    checkId("kem_id", kemId);
    checkId("kdf_id", kdfId);
    checkId("aead_id", aeadId);
    return new HpkeParameterSpec(
        kemId,
        kdfId,
        aeadId,
        info == null || info.length == 0 ? Utils.EMPTY_ARRAY : info.clone(),
        encapsulation == null ? null : encapsulation.clone());
  }

  /**
   * Adapts ACCP or JDK parameters without checking suite support; see {@link HpkeSuite#require}.
   *
   * @throws InvalidAlgorithmParameterException if {@code params} is null, of another type, a JDK
   *     spec with a PSK or an auth key, or a JDK spec whose class the adapter does not recognize
   */
  static HpkeParameterSpec from(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (params == null) {
      throw new InvalidAlgorithmParameterException(
          "An HpkeParameterSpec (or, on JDK 26+, javax.crypto.spec.HPKEParameterSpec) must be"
              + " provided");
    }
    if (params instanceof HpkeParameterSpec) {
      return (HpkeParameterSpec) params;
    }
    if (JdkSpec.CLASS == null && JDK_SPEC_CLASS.equals(params.getClass().getName())) {
      throw new InvalidAlgorithmParameterException(
          unadaptableJdkSpecMessage(JdkSpec.UNRECOGNIZED_METHODS));
    }
    if (JdkSpec.CLASS == null || !JdkSpec.CLASS.isInstance(params)) {
      throw new InvalidAlgorithmParameterException(
          "Unsupported params type: " + params.getClass().getName());
    }
    try {
      final Object p = params;
      return fromComponents(
          (int) JdkSpec.KEM_ID.invokeExact(p),
          (int) JdkSpec.KDF_ID.invokeExact(p),
          (int) JdkSpec.AEAD_ID.invokeExact(p),
          (byte[]) (Object) JdkSpec.INFO.invokeExact(p),
          (byte[]) (Object) JdkSpec.ENCAPSULATION.invokeExact(p),
          (Object) JdkSpec.PSK.invokeExact(p),
          (byte[]) (Object) JdkSpec.PSK_ID.invokeExact(p),
          (Object) JdkSpec.AUTH_KEY.invokeExact(p));
    } catch (final InvalidAlgorithmParameterException | RuntimeException | Error ex) {
      throw ex;
    } catch (final Throwable t) {
      // The accessors declare no checked exceptions, so this is unreachable in practice.
      throw new InvalidAlgorithmParameterException("Cannot read " + JDK_SPEC_CLASS, t);
    }
  }

  /** Converts JDK accessor values independently of reflection, allowing tests on older JDKs. */
  private static HpkeParameterSpec fromComponents(
      final int kemId,
      final int kdfId,
      final int aeadId,
      final byte[] info,
      final byte[] encapsulation,
      final Object psk,
      final byte[] pskId,
      final Object authKey)
      throws InvalidAlgorithmParameterException {
    if (psk != null || (pskId != null && pskId.length != 0)) {
      throw new InvalidAlgorithmParameterException("HPKE PSK mode is not supported");
    }
    if (authKey != null) {
      throw new InvalidAlgorithmParameterException("HPKE auth mode is not supported");
    }
    return create(kemId, kdfId, aeadId, info, encapsulation);
  }

  /**
   * The method names the JDK-spec adapter does not know, sorted. A new public method may mean a new
   * field that the adapter would silently drop.
   */
  static List<String> unknownJdkSpecMethods(final Collection<String> methodNames) {
    final Set<String> unknown = new TreeSet<>(methodNames);
    unknown.removeAll(KNOWN_JDK_SPEC_METHODS);
    return new ArrayList<>(unknown);
  }

  /**
   * The error for a JDK spec that the adapter cannot convert: {@code unrecognized} lists the JDK
   * class's unknown methods, or is null if the class could not be read at all.
   */
  static String unadaptableJdkSpecMessage(final List<String> unrecognized) {
    final String why =
        unrecognized == null
            ? "ACCP cannot read " + JDK_SPEC_CLASS + " on this JDK"
            : "ACCP does not recognize method(s) "
                + unrecognized
                + " of "
                + JDK_SPEC_CLASS
                + " on this JDK";
    return why + "; use " + HpkeParameterSpec.class.getName() + " or upgrade ACCP";
  }

  private static void checkId(final String name, final int id) {
    if (id < 0 || id > 0xFFFF) {
      throw new IllegalArgumentException(name + " must be in [0, 65535]: " + id);
    }
  }

  /**
   * Returns a copy with the given {@code info}. Empty info is already the default and is rejected.
   * The input array is defensively copied.
   *
   * @param info the nonempty context info
   * @return a spec with the given info and all other parameters unchanged
   * @throws NullPointerException if {@code info} is null
   * @throws IllegalArgumentException if {@code info} is empty
   */
  public HpkeParameterSpec withInfo(final byte[] info) {
    Objects.requireNonNull(info, "info must not be null");
    if (info.length == 0) {
      throw new IllegalArgumentException("info is empty");
    }
    return new HpkeParameterSpec(kemId, kdfId, aeadId, info.clone(), encapsulation);
  }

  /**
   * Returns a copy with the recipient's KEM encapsulation ({@code enc}), defensively copying the
   * input array.
   *
   * @param encapsulation the sender's KEM encapsulation
   * @return a spec with the given encapsulation and all other parameters unchanged
   * @throws NullPointerException if {@code encapsulation} is null
   */
  public HpkeParameterSpec withEncapsulation(final byte[] encapsulation) {
    Objects.requireNonNull(encapsulation, "encapsulation must not be null");
    return new HpkeParameterSpec(kemId, kdfId, aeadId, info, encapsulation.clone());
  }

  /**
   * Returns the KEM id.
   *
   * @return the KEM id
   */
  public int kem_id() {
    return kemId;
  }

  /**
   * Returns the KDF id.
   *
   * @return the KDF id
   */
  public int kdf_id() {
    return kdfId;
  }

  /**
   * Returns the AEAD id.
   *
   * @return the AEAD id
   */
  public int aead_id() {
    return aeadId;
  }

  /**
   * Returns a copy of {@code info}; an empty array if none was set.
   *
   * @return a defensive copy of the context info
   */
  public byte[] info() {
    return info.clone();
  }

  /**
   * Returns a copy of the KEM encapsulation, or null if none was set.
   *
   * @return a defensive copy of the encapsulation, or null
   */
  public byte[] encapsulation() {
    return encapsulation == null ? null : encapsulation.clone();
  }

  // Internal accessors avoid copies; callers must not modify the returned arrays.
  byte[] infoInternal() {
    return info;
  }

  byte[] encapsulationInternal() {
    return encapsulation;
  }

  /** Compares suite ids, {@code info}, and encapsulation by value. */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof HpkeParameterSpec)) {
      return false;
    }
    final HpkeParameterSpec other = (HpkeParameterSpec) obj;
    return kemId == other.kemId
        && kdfId == other.kdfId
        && aeadId == other.aeadId
        && Arrays.equals(info, other.info)
        && Arrays.equals(encapsulation, other.encapsulation);
  }

  /** Returns a hash of the suite ids, {@code info}, and encapsulation. */
  @Override
  public int hashCode() {
    int result = kemId;
    result = 31 * result + kdfId;
    result = 31 * result + aeadId;
    result = 31 * result + Arrays.hashCode(info);
    result = 31 * result + Arrays.hashCode(encapsulation);
    return result;
  }

  /**
   * Returns suite ids and the lengths of {@code info} and encapsulation, without their contents.
   */
  @Override
  public String toString() {
    return String.format(
        "HpkeParameterSpec{kem_id=0x%04x, kdf_id=0x%04x, aead_id=0x%04x, info=%d bytes,"
            + " encapsulation=%s}",
        kemId,
        kdfId,
        aeadId,
        info.length,
        encapsulation == null ? "none" : encapsulation.length + " bytes");
  }

  /**
   * Lazy, cached reflection preserves JDK 8 compatibility. Handles return {@code int} or {@code
   * Object} to avoid linking newer types such as {@code AsymmetricKey}. {@code CLASS} stays null if
   * lookup fails or unknown instance methods could hide new fields.
   */
  private static final class JdkSpec {
    static final Class<?> CLASS;
    static final MethodHandle KEM_ID;
    static final MethodHandle KDF_ID;
    static final MethodHandle AEAD_ID;
    static final MethodHandle INFO;
    static final MethodHandle ENCAPSULATION;
    static final MethodHandle PSK;
    static final MethodHandle PSK_ID;
    static final MethodHandle AUTH_KEY;
    // Unknown methods that prevented adaptation, or null for other lookup failures.
    static final List<String> UNRECOGNIZED_METHODS;

    static {
      Class<?> cls = null;
      List<String> unrecognized = null;
      MethodHandle kemId = null;
      MethodHandle kdfId = null;
      MethodHandle aeadId = null;
      MethodHandle info = null;
      MethodHandle encapsulation = null;
      MethodHandle psk = null;
      MethodHandle pskId = null;
      MethodHandle authKey = null;
      try {
        // A null loader is the bootstrap loader, which defines javax.crypto.spec.
        final Class<?> c = Class.forName(JDK_SPEC_CLASS, false, null);
        kemId = accessor(c, "kem_id", int.class);
        kdfId = accessor(c, "kdf_id", int.class);
        aeadId = accessor(c, "aead_id", int.class);
        info = accessor(c, "info", Object.class);
        encapsulation = accessor(c, "encapsulation", Object.class);
        psk = accessor(c, "psk", Object.class);
        pskId = accessor(c, "psk_id", Object.class);
        authKey = accessor(c, "authKey", Object.class);
        final Set<String> names = new HashSet<>();
        for (final Method m : c.getMethods()) {
          if (!Modifier.isStatic(m.getModifiers())) {
            names.add(m.getName());
          }
        }
        final List<String> unknown = unknownJdkSpecMethods(names);
        if (unknown.isEmpty()) {
          cls = c;
        } else {
          unrecognized = Collections.unmodifiableList(unknown);
        }
      } catch (final ReflectiveOperationException | LinkageError | RuntimeException ex) {
        // Not on this JDK (or not usable): JDK specs are then rejected as an unsupported type.
        cls = null;
      }
      CLASS = cls;
      UNRECOGNIZED_METHODS = unrecognized;
      KEM_ID = kemId;
      KDF_ID = kdfId;
      AEAD_ID = aeadId;
      INFO = info;
      ENCAPSULATION = encapsulation;
      PSK = psk;
      PSK_ID = pskId;
      AUTH_KEY = authKey;
    }

    /** A handle for {@code cls.name()} typed {@code (Object) -> returnType}. */
    private static MethodHandle accessor(
        final Class<?> cls, final String name, final Class<?> returnType)
        throws ReflectiveOperationException {
      return MethodHandles.publicLookup()
          .unreflect(cls.getMethod(name))
          .asType(MethodType.methodType(returnType, Object.class));
    }

    private JdkSpec() {}
  }
}
