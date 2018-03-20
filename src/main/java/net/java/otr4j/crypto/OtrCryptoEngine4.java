package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;
import org.bouncycastle.crypto.digests.SHAKEDigest;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static nl.dannyvanheumen.joldilocks.Ed448.primeOrder;
import static nl.dannyvanheumen.joldilocks.Scalars.decodeLittleEndian;

/**
 * Crypto engine for OTRv4.
 */
public final class OtrCryptoEngine4 {

    /**
     * Bit-size for SHAKE-256.
     */
    private static final int SHAKE_256_LENGTH_BITS = 256;

    /**
     * Length of a fingerprint in bytes.
     */
    static final int FINGERPRINT_LENGTH_BYTES = 56;

    /**
     * Length of HashToScalar array of bytes.
     */
    private static final int HASH_TO_SCALAR_LENGTH_BYTES = 64;

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
     * "KDF_1(usageID || values, output_size) = SHAKE-256("OTRv4" || usageID || values, size)"
     *
     * @param outputSize The size of the derivative output.
     * @param dst        The destination byte array, with 32 bytes available for KDF_1 result.
     * @param offset     The offset position to start writing to the destination byte array.
     * @param input      The input data to KDF_1.
     */
    // TODO Consider adding parameter for usage ID, as all usages of kdf1 concatenate the single byte usage ID manually right now.
    public static void kdf1(@Nonnull final byte[] dst, final int offset, @Nonnull final byte[] input, final int outputSize) {
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(OTR4_PREFIX, 0, OTR4_PREFIX.length);
        digest.update(input, 0, input.length);
        digest.doFinal(dst, offset, outputSize);
    }

    /**
     * KDF_2 key derivation function.
     * <p>
     * "KDF_2(values, size) = SHAKE-256(values, size)"
     *
     * @param dst    The destination byte array, with 64 bytes available for KDF_2 result.
     * @param offset The offset position to start writing to the destination byte array.
     * @param input  The input data to KDF_2.
     */
    public static void kdf2(@Nonnull final byte[] dst, final int offset, @Nonnull final byte[] input, final int outputSize) {
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(input, 0, input.length);
        digest.doFinal(dst, offset, outputSize);
    }

    /**
     * HashToScalar.
     *
     * As defined in section "HashToScalar" in OTRv4 specification.
     *
     * @param d array of bytes
     * @return Returns derived scalar value.
     */
    @Nonnull
    public static BigInteger hashToScalar(@Nonnull final byte[] d) {
        //    Compute h = KDF_1(d, 64) as an unsigned value, little-endian.
        final byte[] hashedD = new byte[HASH_TO_SCALAR_LENGTH_BYTES];
        kdf1(hashedD, 0, d, HASH_TO_SCALAR_LENGTH_BYTES);
        final BigInteger h = decodeLittleEndian(hashedD);
        //    Return h (mod q)
        return h.mod(primeOrder());
    }
}
