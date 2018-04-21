package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static nl.dannyvanheumen.joldilocks.Ed448.cofactor;
import static nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase;
import static nl.dannyvanheumen.joldilocks.Points.checkIdentity;
import static nl.dannyvanheumen.joldilocks.Scalars.decodeLittleEndian;
import static org.bouncycastle.util.Arrays.clear;

/**
 * ECDH keypair based on Ed448-Goldilocks.
 */
public final class ECDHKeyPair {

    /**
     * Length of the secret key in bytes.
     */
    static final int LENGTH_SECRET_KEY_BYTES = 57;

    /**
     * Context c, used in signing.
     */
    private static final byte[] SIGNING_CONTEXT_C = new byte[0];

    private final BigInteger secretKey;
    private final Point publicKey;

    ECDHKeyPair(@Nonnull final BigInteger secretKey) {
        this.secretKey = requireNonNull(secretKey);
        this.publicKey = multiplyByBase(secretKey);
    }

    /**
     * Generate an ECDH keypair.
     * <p>
     * Procedure implemented as described in "Generating ECDH and DH keys" in OTRv4 specification.
     *
     * @param random SecureRandom instance
     * @return Returns ECDH keypair.
     */
    @Nonnull
    public static ECDHKeyPair generate(@Nonnull final SecureRandom random) {
        //  - pick a random value r (57 bytes)
        //  - generate 'h' = KDF_1(0x01 || r, 57).
        final byte[] r = new byte[LENGTH_SECRET_KEY_BYTES + 1];
        random.nextBytes(r);
        return generate(r);
    }

    /**
     * Generate an ECDH key pair based on provided random value.
     *
     * @param r The secure random data. (Requires byte-array of 58 bytes. The first byte will be overwritten in the
     *         process.)
     * @return Returns the generated ECDH key pair.
     */
    @Nonnull
    public static ECDHKeyPair generate(@Nonnull final byte[] r) {
        requireLengthExactly(LENGTH_SECRET_KEY_BYTES + 1, r);
        r[0] = 0x01;
        final byte[] h = new byte[57];
        kdf1(h, 0, r, LENGTH_SECRET_KEY_BYTES);
        //  - prune 'h': the two least significant bits of the first byte are cleared, all
        //    eight bits of the last byte are cleared, and the highest bit of the second
        //    to last byte is set.
        h[0] &= 0b11111100;
        h[56] = 0;
        h[55] &= 0b01111111;
        //  - Interpret the buffer as the little-endian integer, forming the secret scalar
        //    's'.
        final BigInteger s = decodeLittleEndian(h);
        //  - Securely delete 'r' and 'h'.
        clear(r);
        clear(h);
        //  - return our_ecdh.public = G * s, our_ecdh.secret = s
        return new ECDHKeyPair(s);
    }

    /**
     * Get public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getPublicKey() {
        return this.publicKey;
    }

    /**
     * Get secret key.
     * <p>
     * The secret key is intentionally not made public. It should only be used in a package-local logic such that we can
     * prevent unintended exposures of secret data.
     *
     * @return Returns the secret key.
     */
    @Nonnull
    BigInteger getSecretKey() {
        return this.secretKey;
    }

    /**
     * Sign provided message using the secret key that is maintained inside this key pair.
     *
     * @param message The message to be signed.
     * @return Returns the signature for the provided message.
     */
    @Nonnull
    public byte[] sign(@Nonnull final byte[] message) {
        return Ed448.sign(this.secretKey, SIGNING_CONTEXT_C, message);
    }

    /**
     * Verify a message given public key and signature.
     *
     * @param publicKey The public key to verify the signature.
     * @param message   The message to be verified.
     * @param signature The signature with which to verify the message.
     * @throws OtrCryptoException In case message verification fails.
     */
    public static void verify(@Nonnull final Point publicKey, @Nonnull final byte[] message, @Nonnull final byte[] signature) throws OtrCryptoException {
        try {
            Ed448.verify(SIGNING_CONTEXT_C, publicKey, message, signature);
        } catch (final Ed448.SignatureVerificationFailedException e) {
            throw new OtrCryptoException("Signature verification failed.", e);
        }
    }

    /**
     * Generate the ECDH shared secret for other party's public key.
     *
     * @param otherPublicKey The other party's public key.
     * @return Returns the shared secret point.
     */
    @Nonnull
    public Point generateSharedSecret(@Nonnull final Point otherPublicKey) throws OtrCryptoException {
        final Point sharedSecret = otherPublicKey.multiply(cofactor()).multiply(this.secretKey);
        // TODO is 'checkIdentity' method sufficient to discover all illegal public keys? (This problem solves itself once we switch to byte-arrays as representation of public keys.
        if (checkIdentity(sharedSecret)) {
            throw new OtrCryptoException("Illegal ECDH public key.");
        }
        return sharedSecret;
    }
}
