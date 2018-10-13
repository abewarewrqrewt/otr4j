package net.java.otr4j.crypto.ed448;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import javax.annotation.Nonnull;

import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.Integers.requireAtLeast;

final class Shake256 {

    /**
     * Bit-size for SHAKE-256.
     */
    private static final int SHAKE_256_LENGTH_BITS = 256;

    private Shake256() {
        // No need to instantiate utility class.
    }

    /**
     * SHAKE-256 hash function.
     *
     * @param input      The input data for the hash function.
     * @param outputSize The output size of the digest.
     */
    @Nonnull
    static byte[] shake256(@Nonnull final byte[] input, final int outputSize) {
        requireAtLeast(0, outputSize);
        assert !allZeroBytes(input) : "Expected non-zero bytes for input. This may indicate that a critical bug is present, or it may be a false warning.";
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(input, 0, input.length);
        final byte[] result = new byte[outputSize];
        digest.doFinal(result, 0, outputSize);
        return result;
    }
}
