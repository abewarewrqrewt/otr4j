package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * The Shared Secret mechanism used in OTRv4.
 */
// TODO consider what we would need to do to reuse the same memory more. Right now we replace one reference by another, but we rely on the instances being cleaned up by the GC.
final class SharedSecret4 {

    private static final int BRACE_KEY_LENGTH_BYTES = 32;
    private static final int K_LENGTH_BYTES = 64;
    private static final int SSID_LENGTH_BYTES = 8;

    private static final byte[] USAGE_ID_BRACE_KEY_FROM_DH = new byte[]{0x02};
    private static final byte[] USAGE_ID_BRACE_KEY_FROM_BRACE_KEY = new byte[]{0x03};
    private static final byte[] USAGE_ID_MIXED_SHARED_SECRET = new byte[]{0x04};
    private static final byte[] USAGE_ID_SSID_GENERATION = new byte[]{0x05};

    /**
     * Secure random source.
     */
    private final SecureRandom random;

    /**
     * The 3072-bit DH shared secret computed from a DH key exchange, serialized as a big-endian unsigned integer.
     */
    private DHKeyPair dhKeyPair;

    /**
     * Other party's DH public key.
     */
    private BigInteger theirDHPublicKey;

    /**
     * Shared key by DH key exchange.
     */
    // FIXME consider preinitializing and finalizing with fixed byte array, constantly overwriting array content.
    // FIXME check if we need to persist this as field, or if we can treat it only as a local variable.
    private byte[] k_dh;

    /**
     * The serialized ECDH shared secret computed from an ECDH exchange, serialized as a
     * {@link nl.dannyvanheumen.joldilocks.Point}.
     */
    private ECDHKeyPair ecdhKeyPair;

    /**
     * Other party's ECDH public key.
     */
    private Point theirECDHPublicKey;

    /**
     * Shared key by ECDH key exchange.
     */
    // FIXME consider preinitializing and finalizing with fixed byte array, constantly overwriting array content.
    private byte[] k_ecdh;

    /**
     * Either a hash of the shared DH key: 'KDF_1(0x02 || k_dh, 32)' (every third DH ratchet) or a hash of the previous
     * 'brace_key: KDF_1(0x03 || brace_key, 32)'.
     */
    private final byte[] braceKey = new byte[BRACE_KEY_LENGTH_BYTES];

    /**
     * The Mixed shared secret 'K' is the final shared secret derived from both the brace key and ECDH shared secrets:
     * 'KDF_1(0x04 || K_ecdh || brace_key, 64)'.
     */
    private final byte[] k = new byte[K_LENGTH_BYTES];

    /**
     * The SSID (session ID) that is derived from the Mixed shared secret key.
     */
    private final byte[] ssid = new byte[SSID_LENGTH_BYTES];

    SharedSecret4(@Nonnull final SecureRandom random, @Nonnull final DHKeyPair dh, @Nonnull final ECDHKeyPair ecdh) {
        this.random = requireNonNull(random);
        this.dhKeyPair = requireNonNull(dh);
        this.theirDHPublicKey = null;
        this.k_dh = null;
        this.ecdhKeyPair = requireNonNull(ecdh);
        this.theirECDHPublicKey = null;
        this.k_ecdh = null;
    }

    /**
     * Get mixed shared secret K.
     *
     * @return Mixed shared secret K.
     */
    byte[] getK() {
        requireInitialization();
        return this.k.clone();
    }

    /**
     * Get the current SSID (Session ID).
     *
     * @return Session ID a.k.a. SSID
     */
    byte[] getSSID() {
        requireInitialization();
        return this.ssid.clone();
    }

    /**
     * Rotate our key pairs in the shared secret.
     *
     * @param ratchetIteration The ratchet iteration a.k.a. 'i'.
     * @throws OtrCryptoException Thrown in case of failures generating the new cryptographic material.
     */
    void rotateOurKeys(final int ratchetIteration) throws OtrCryptoException {
        this.ecdhKeyPair = ECDHKeyPair.generate(this.random);
        regenerateECDHSharedSecret();
        if (ratchetIteration % 3 == 0) {
            this.dhKeyPair = DHKeyPair.generate(this.random);
        }
        regenerateBraceKey(ratchetIteration);
        regenerateMixedSharedSecret();
        regenerateSSID();
    }

    /**
     * Rotate their public keys in the shared secret.
     *
     * @param ratchetIteration   The ratchet iteration a.k.a. 'i'.
     * @param theirECDHPublicKey Their ECDH public key.
     * @param theirDHPublicKey   Their DH public key.
     * @throws OtrCryptoException THrown in case of failures generating the new cryptograhic material.
     */
    void rotateTheirKeys(final int ratchetIteration, @Nonnull final Point theirECDHPublicKey,
                @Nonnull final BigInteger theirDHPublicKey) throws OtrCryptoException {
        // FIXME verify requirements of public key before accepting it.
        this.theirECDHPublicKey = requireNonNull(theirECDHPublicKey);
        regenerateECDHSharedSecret();
        // FIXME we probably do not receive a new DH public key on every message. Hence we need to conditionally rotate DH public keys only on specific iterations.
        this.theirDHPublicKey = requireNonNull(theirDHPublicKey);
        regenerateBraceKey(ratchetIteration);
        // FIXME securely delete our_ecdh.secret.
        regenerateMixedSharedSecret();
        regenerateSSID();
    }

    private void regenerateECDHSharedSecret() throws OtrCryptoException {
        this.ecdhKeyPair.generateSharedSecret(this.theirECDHPublicKey).encodeTo(this.k_ecdh, 0);
    }

    private void regenerateBraceKey(final int ratchetIteration) {
        if (ratchetIteration % 3 == 0) {
            this.k_dh = asUnsignedByteArray(this.dhKeyPair.generateSharedSecret(this.theirDHPublicKey));
            kdf1(this.braceKey, 0, concatenate(USAGE_ID_BRACE_KEY_FROM_DH, this.k_dh), BRACE_KEY_LENGTH_BYTES);
            // FIXME securely delete our_dh.secret, k_dh.
        } else {
            kdf1(this.braceKey, 0, concatenate(USAGE_ID_BRACE_KEY_FROM_BRACE_KEY, this.braceKey), BRACE_KEY_LENGTH_BYTES);
        }
    }

    private void regenerateMixedSharedSecret() {
        kdf1(this.k, 0, concatenate(USAGE_ID_MIXED_SHARED_SECRET, this.k_ecdh, this.braceKey), K_LENGTH_BYTES);
    }

    private void regenerateSSID() {
        kdf1(this.ssid, 0, concatenate(USAGE_ID_SSID_GENERATION, this.k), SSID_LENGTH_BYTES);
    }

    /**
     * Method for verifying that SharedSecret4 is initialized before permitting use of this method.
     */
    private void requireInitialization() {
        if (this.theirDHPublicKey == null || this.k_dh == null || this.theirECDHPublicKey == null || this.k_ecdh == null) {
            throw new IllegalStateException("Instance has not been initialized with other party's public key material. Please rotate session keys before first acquiring key material.");
        }
    }
}
