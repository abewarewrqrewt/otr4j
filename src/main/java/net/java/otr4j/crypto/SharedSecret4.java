package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * The Shared Secret mechanism used in OTRv4.
 */
// TODO consider what we would need to do to reuse the same memory more. Right now we replace one reference by another, but we rely on the instances being cleaned up by the GC.
// FIXME investigate what we need to clean additionally for Point and BigInteger calculations where we use temporary instances during computation.
// FIXME use of concatenate(...) to concat byte arrays, but intermediate result is not cleared.
// FIXME write tests for testing key rotation.
final class SharedSecret4 {

    private static final int BRACE_KEY_LENGTH_BYTES = 32;
    private static final int K_LENGTH_BYTES = 64;
    private static final int SSID_LENGTH_BYTES = 8;

    private static final byte[] USAGE_ID_BRACE_KEY_FROM_DH = new byte[]{0x02};
    private static final byte[] USAGE_ID_BRACE_KEY_FROM_BRACE_KEY = new byte[]{0x03};
    private static final byte[] USAGE_ID_MIXED_SHARED_SECRET = new byte[]{0x04};
    private static final byte[] USAGE_ID_SSID_GENERATION = new byte[]{0x05};

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

    /**
     * The 3072-bit DH shared secret computed from a DH key exchange, serialized as a big-endian unsigned integer.
     */
    @Nonnull
    private DHKeyPair dhKeyPair;

    /**
     * Other party's DH public key.
     */
    @Nonnull
    private BigInteger theirDHPublicKey;

    /**
     * The serialized ECDH shared secret computed from an ECDH exchange, serialized as a
     * {@link nl.dannyvanheumen.joldilocks.Point}.
     */
    @Nonnull
    private ECDHKeyPair ecdhKeyPair;

    /**
     * Other party's ECDH public key.
     */
    @Nonnull
    private Point theirECDHPublicKey;

    SharedSecret4(@Nonnull final DHKeyPair ourDHKeyPair, @Nonnull final ECDHKeyPair ourECDHKeyPair,
                  @Nonnull final BigInteger theirDHPublicKey, @Nonnull final Point theirECDHPublicKey)
        throws OtrCryptoException {

        this.ecdhKeyPair = requireNonNull(ourECDHKeyPair);
        this.theirECDHPublicKey = requireNonNull(theirECDHPublicKey);
        this.dhKeyPair = requireNonNull(ourDHKeyPair);
        this.theirDHPublicKey = requireNonNull(theirDHPublicKey);
        regenerateK(0);
        regenerateSSID();
    }

    /**
     * Get mixed shared secret K.
     *
     * @return Mixed shared secret K.
     */
    byte[] getK() {
        return this.k.clone();
    }

    /**
     * Get the current SSID (Session ID).
     *
     * @return Session ID a.k.a. SSID
     */
    byte[] getSSID() {
        return this.ssid.clone();
    }

    /**
     * Rotate our key pairs in the shared secret.
     *
     * @param ratchetIteration The ratchet iteration a.k.a. 'i'.
     * @throws OtrCryptoException Thrown in case of failures generating the new cryptographic material.
     */
    // FIXME is a DHKeyPair always expected/required?
    void rotateOurKeys(final int ratchetIteration, @Nonnull final ECDHKeyPair ourECDHKeyPair,
                       @Nullable final DHKeyPair ourDHKeyPair) throws OtrCryptoException {
        this.ecdhKeyPair = requireNonNull(ourECDHKeyPair);
        if (ratchetIteration % 3 == 0) {
            this.dhKeyPair = requireNonNull(ourDHKeyPair);
        }
        regenerateK(ratchetIteration);
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
                         @Nullable final BigInteger theirDHPublicKey) throws OtrCryptoException {
        // FIXME verify requirements of public key before accepting it.
        this.theirECDHPublicKey = requireNonNull(theirECDHPublicKey);
        if (ratchetIteration % 3 == 0) {
            // FIXME we probably do not receive a new DH public key on every message. Hence we need to conditionally rotate DH public keys only on specific iterations.
            this.theirDHPublicKey = requireNonNull(theirDHPublicKey);
        }
        // FIXME securely delete our_ecdh.secret.
        regenerateK(ratchetIteration);
        regenerateSSID();
    }

    private void regenerateK(final int ratchetIteration) throws OtrCryptoException {
        final byte[] k_ecdh = this.ecdhKeyPair.generateSharedSecret(this.theirECDHPublicKey).encode();
        if (ratchetIteration % 3 == 0) {
            final byte[] k_dh = asUnsignedByteArray(this.dhKeyPair.generateSharedSecret(this.theirDHPublicKey));
            kdf1(this.braceKey, 0, concatenate(USAGE_ID_BRACE_KEY_FROM_DH, k_dh), BRACE_KEY_LENGTH_BYTES);
            clear(k_dh);
            // FIXME securely delete our_dh.secret.
        } else {
            kdf1(this.braceKey, 0, concatenate(USAGE_ID_BRACE_KEY_FROM_BRACE_KEY, this.braceKey),
                BRACE_KEY_LENGTH_BYTES);
        }
        kdf1(this.k, 0, concatenate(USAGE_ID_MIXED_SHARED_SECRET, k_ecdh, this.braceKey), K_LENGTH_BYTES);
        clear(k_ecdh);
    }

    private void regenerateSSID() {
        kdf1(this.ssid, 0, concatenate(USAGE_ID_SSID_GENERATION, this.k), SSID_LENGTH_BYTES);
    }
}
