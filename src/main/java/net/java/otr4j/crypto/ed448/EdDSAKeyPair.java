package net.java.otr4j.crypto.ed448;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.ec.rfc8032.Ed448;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.Point.decodePoint;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.SecureRandoms.random;
import static org.bouncycastle.math.ec.rfc8032.Ed448.PUBLIC_KEY_SIZE;
import static org.bouncycastle.math.ec.rfc8032.Ed448.SECRET_KEY_SIZE;
import static org.bouncycastle.math.ec.rfc8032.Ed448.generatePublicKey;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.copyOfRange;

/**
 * EdDSA key pair.
 */
public final class EdDSAKeyPair {

    /**
     * Length in bits of SHAKE-256.
     */
    private static final int SHAKE_256_LENGTH_BITS = 256;

    /**
     * Context value as applied in OTRv4.
     */
    private static final byte[] ED448_CONTEXT = new byte[0];

    private final byte[] symmetricKey;
    private final byte[] publicKey;

    private EdDSAKeyPair(@Nonnull final byte[] symmetricKey, @Nonnull final byte[] publicKey) {
        assert !allZeroBytes(symmetricKey);
        this.symmetricKey = requireLengthExactly(SECRET_KEY_SIZE, symmetricKey);
        assert !allZeroBytes(publicKey);
        this.publicKey = requireLengthExactly(PUBLIC_KEY_SIZE, publicKey);
    }

    /**
     * Generate a EdDSA (long-term) key pair. The key pair itself will be requested from the Engine host. This method is
     * there for convenience, to be used by Engine host implementations.
     *
     * @param random Source of secure random data.
     * @return Returns the generated key pair.
     */
    @Nonnull
    public static EdDSAKeyPair generate(@Nonnull final SecureRandom random) {
        final byte[] symmetricKey = random(random, new byte[SECRET_KEY_SIZE]);
        final byte[] publicKey = new byte[PUBLIC_KEY_SIZE];
        generatePublicKey(symmetricKey, 0, publicKey, 0);
        return new EdDSAKeyPair(symmetricKey, publicKey);
    }

    /**
     * Verify a signature for a message, given the public key.
     *
     * @param publicKey The public key of the key pair that generated the signature.
     * @param message   The message that was signed.
     * @param signature The signature.
     * @throws ValidationException In case we fail to validate the message against the provided signature.
     */
    // TODO in some cases, a non-static method may be desirable because the keypair is available.
    public static void verify(@Nonnull final Point publicKey, @Nonnull final byte[] message, @Nonnull final byte[] signature)
            throws ValidationException {
        assert !allZeroBytes(signature) : "Expected random data for signature instead of all zero-bytes.";
        if (!Ed448.verify(signature, 0, publicKey.p.encode(), 0, ED448_CONTEXT, message, 0, message.length)) {
            throw new ValidationException("Signature is not valid for provided message.");
        }
    }

    /**
     * Sign message.
     * <p>
     * Signs the message using the default context as used in OTRv4.
     *
     * @param message The message to be signed.
     * @return Returns the signature that corresponds to the message.
     */
    @Nonnull
    public byte[] sign(@Nonnull final byte[] message) {
        final byte[] signature = new byte[Ed448.SIGNATURE_SIZE];
        Ed448.sign(this.symmetricKey, 0, ED448_CONTEXT, message, 0, message.length, signature, 0);
        return signature;
    }

    /**
     * Acquire public key from the key pair.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getPublicKey() {
        try {
            return decodePoint(this.publicKey);
        } catch (ValidationException e) {
            throw new IllegalStateException("BUG: The public key is expected to always be correct as it is part of the EdDSA key pair.");
        }
    }

    /**
     * Acquire secret key from the key pair.
     *
     * @return Returns secret key.
     */
    @Nonnull
    public Scalar getSecretKey() {
        // FIXME extract common code related to SHAKE256
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(this.symmetricKey, 0, this.symmetricKey.length);
        final byte[] h = new byte[2 * SECRET_KEY_SIZE];
        digest.doFinal(h, 0, h.length);
        final byte[] secretKey = copyOfRange(h, 0, SECRET_KEY_SIZE);
        clear(h);
        secretKey[0] &= 0b11111100;
        secretKey[56] = 0;
        secretKey[55] |= 0b10000000;
        try {
            return decodeScalar(secretKey);
        } finally {
            clear(secretKey);
        }
    }
}
