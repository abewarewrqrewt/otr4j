package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.shake256;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static nl.dannyvanheumen.joldilocks.Ed448.cofactor;
import static nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase;
import static nl.dannyvanheumen.joldilocks.Points.checkIdentity;
import static nl.dannyvanheumen.joldilocks.Scalars.decodeLittleEndian;
import static org.bouncycastle.util.Arrays.clear;

/**
 * ECDH keypair based on Ed448-Goldilocks.
 */
public final class ECDHKeyPair implements AutoCloseable {

    /**
     * Length of the secret key in bytes.
     */
    static final int SECRET_KEY_LENGTH_BYTES = 57;

    private BigInteger secretKey;

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
        final byte[] r = new byte[SECRET_KEY_LENGTH_BYTES];
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
        //  - pick a random value r (57 bytes)
        requireLengthExactly(SECRET_KEY_LENGTH_BYTES, r);
        assert !allZeroBytes(r) : "Expected 57 bytes of random data, instead of all zeroes.";
        //  - Hash the 'r' using 'SHAKE-256(r, 114)'. Store the digest in a
        //    114-byte buffer. Only the lower 57 bytes (denoted 'h') are used for
        //    generating the public key.
        final byte[] h = new byte[SECRET_KEY_LENGTH_BYTES];
        {
            final byte[] buffer = new byte[114];
            shake256(buffer, 0, r, buffer.length);
            System.arraycopy(buffer, 0, h, 0, SECRET_KEY_LENGTH_BYTES);
        }
        //  - prune 'h': the two least significant bits of the first byte are cleared, all
        //    eight bits of the last byte are cleared, and the highest bit of the second
        //    to last byte is set.
        assert !allZeroBytes(h) : "Expected random data, instead of all-zero byte-array.";
        h[0] &= 0b11111100;
        h[SECRET_KEY_LENGTH_BYTES - 1] = 0;
        h[SECRET_KEY_LENGTH_BYTES - 2] |= 0b10000000;
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
     * @return Returns the secret key or null if resource is already closed.
     */
    // TODO is this method really needed?
    @Nullable
    BigInteger getSecretKey() {
        return this.secretKey;
    }

    /**
     * Generate the ECDH shared secret for other party's public key.
     *
     * @param otherPublicKey The other party's public key.
     * @return Returns the shared secret point.
     * @throws OtrCryptoException In case of illegal ECDH public key.
     */
    @Nonnull
    public Point generateSharedSecret(@Nonnull final Point otherPublicKey) throws OtrCryptoException {
        if (this.secretKey == null) {
            throw new IllegalStateException("Secret key material has been cleared. Only public key is still available.");
        }
        final Point sharedSecret = otherPublicKey.multiply(cofactor()).multiply(this.secretKey);
        // TODO is 'checkIdentity' method sufficient to discover all illegal public keys? (This problem solves itself once we switch to byte-arrays as representation of public keys.
        if (checkIdentity(sharedSecret)) {
            throw new OtrCryptoException("Illegal ECDH public key.");
        }
        return sharedSecret;
    }

    /**
     * Clear the secret key of the ECDH key pair.
     */
    // TODO clearing secret key does not guarantee secret key material is lost. Just that reference is gone.
    @Override
    public void close() {
        this.secretKey = null;
    }
}
