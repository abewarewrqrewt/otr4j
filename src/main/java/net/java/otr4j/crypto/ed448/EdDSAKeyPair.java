package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Ed448KeyPair;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;

/**
 * EdDSA key pair.
 */
public final class EdDSAKeyPair {

    /**
     * Context value as applied in OTRv4.
     */
    private static final byte[] ED448_CONTEXT = new byte[0];

    private final Ed448KeyPair keypair;

    private EdDSAKeyPair(@Nonnull final Ed448KeyPair keypair) {
        this.keypair = requireNonNull(keypair);
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
        return new EdDSAKeyPair(Ed448KeyPair.create(Ed448.generateSymmetricKey(random)));
    }

    /**
     * Verify a signature for a message, given the public key.
     *
     * @param publicKey The public key of the key pair that generated the signature.
     * @param message   The message that was signed.
     * @param signature The signature.
     * @throws ValidationException In case we fail to validate the message against the provided signature.
     */
    public static void verify(@Nonnull final Point publicKey, @Nonnull final byte[] message, @Nonnull final byte[] signature)
            throws ValidationException {
        assert !allZeroBytes(signature) : "Expected random data for signature instead of all zero-bytes.";
        try {
            Ed448.verify(ED448_CONTEXT, publicKey.p, message, signature);
        } catch (final Ed448.SignatureVerificationFailedException e) {
            throw new ValidationException("Signature is not valid for provided message.", e);
        }
    }

    /**
     * Sign message.
     *
     * Signs the message using the default context as used in OTRv4.
     *
     * @param message The message to be signed.
     * @return Returns the signature that corresponds to the message.
     */
    @Nonnull
    public byte[] sign(@Nonnull final byte[] message) {
        return this.keypair.sign(ED448_CONTEXT, message);
    }

    /**
     * Acquire public key from the key pair.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getPublicKey() {
        return new Point(this.keypair.getPublicKey());
    }

    /**
     * Symmetric key.
     *
     * @return Returns symmetric key.
     */
    @Nonnull
    public Scalar getSecretKey() {
        return fromBigInteger(this.keypair.getSecretKey());
    }
}
