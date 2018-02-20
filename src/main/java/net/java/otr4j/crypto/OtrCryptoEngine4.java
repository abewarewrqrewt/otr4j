package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import org.bouncycastle.crypto.digests.SHAKEDigest;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static nl.dannyvanheumen.joldilocks.Ed448.Q;

/**
 * Crypto engine for OTRv4.
 */
public final class OtrCryptoEngine4 {

    /**
     * Bit-size for SHAKE-256.
     */
    static final int SHAKE_256_LENGTH_BITS = 256;

    /**
     * Length of a fingerprint in bytes.
     */
    static final int FINGERPRINT_LENGTH_BYTES = 56;

    /**
     * Length of KDF_1 result in bytes.
     */
    static final int KDF_1_LENGTH_BYTES = 32;

    /**
     * Length of KDF_2 result in bytes.
     */
    static final int KDF_2_LENGTH_BYTES = 64;

    /**
     * Prefix used in key derivation functions.
     */
    private static final byte[] OTR4_PREFIX = new byte[]{'O', 'T', 'R', '4'};

    private OtrCryptoEngine4() {
        // No need to instantiate utility class.
    }

    /**
     * Produce fingerprint for public key.
     *
     * @param dst       The destination byte array to which to write the fingerprint.
     * @param publicKey The public key to fingerprint.
     */
    public static void fingerprint(@Nonnull final byte[] dst, @Nonnull final Point publicKey) {
        requireNonNull(dst);
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        final byte[] encodedPublicKey = publicKey.encode();
        digest.update(encodedPublicKey, 0, encodedPublicKey.length);
        if (digest.doFinal(dst, 0, FINGERPRINT_LENGTH_BYTES) != FINGERPRINT_LENGTH_BYTES) {
            throw new IllegalStateException("Expected exactly " + FINGERPRINT_LENGTH_BYTES + " bytes to be produced for the fingerprint.");
        }
    }

    /**
     * KDF_1 key derivation function.
     * <p>
     * "KDF_1(x) = take_first_32_bytes(SHAKE-256("OTR4" || x))"
     *
     * @param dst    The destination byte array, with 32 bytes available for KDF_1 result.
     * @param offset The offset position to start writing to the destination byte array.
     * @param input  The input data to KDF_1.
     */
    public static void kdf1(@Nonnull final byte[] dst, final int offset, @Nonnull final byte[] input) {
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(OTR4_PREFIX, 0, OTR4_PREFIX.length);
        digest.update(input, 0, input.length);
        digest.doFinal(dst, offset, KDF_1_LENGTH_BYTES);
    }

    /**
     * KDF_2 key derivation function.
     * <p>
     * "KDF_2(x) = take_first_64_bytes(SHAKE-256("OTR4" || x))"
     *
     * @param dst    The destination byte array, with 64 bytes available for KDF_2 result.
     * @param offset The offset position to start writing to the destination byte array.
     * @param input  The input data to KDF_2.
     */
    public static void kdf2(@Nonnull final byte[] dst, final int offset, @Nonnull final byte[] input) {
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(OTR4_PREFIX, 0, OTR4_PREFIX.length);
        digest.update(input, 0, input.length);
        digest.doFinal(dst, offset, KDF_2_LENGTH_BYTES);
    }

    /**
     * KDF key derivation function, for arbitrary-length results.
     *
     * @param dst         The destination byte array.
     * @param offset      The offset position to start writing to the destination.
     * @param lengthBytes The length in bytes of the result.
     * @param input       The input data.
     */
    public static void kdf(@Nonnull final byte[] dst, final int offset, final int lengthBytes, @Nonnull final byte[] input) {
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(input, 0, input.length);
        digest.doFinal(dst, offset, lengthBytes);
    }

    /**
     * HashToScalar.
     *
     * @param d array of bytes
     * @return Returns derived scalar value.
     */
    @Nonnull
    public static BigInteger hashToScalar(@Nonnull final byte[] d) {
        final byte[] hashedD = new byte[KDF_2_LENGTH_BYTES];
        kdf2(hashedD, 0, d);
        return new BigInteger(1, hashedD).mod(Q);
    }
}
