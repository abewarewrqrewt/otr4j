package net.java.otr4j.crypto;

import net.java.otr4j.session.ake.SecurityParameters4;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.DHKeyPair.DH_PRIVATE_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.ECDHKeyPair.LENGTH_SECRET_KEY_BYTES;
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
public final class SharedSecret4 implements AutoCloseable {

    private static final int BRACE_KEY_LENGTH_BYTES = 32;
    private static final int K_LENGTH_BYTES = 64;

    private static final byte[] USAGE_ID_BRACE_KEY_FROM_DH = new byte[]{0x02};
    private static final byte[] USAGE_ID_BRACE_KEY_FROM_BRACE_KEY = new byte[]{0x03};
    private static final byte[] USAGE_ID_MIXED_SHARED_SECRET = new byte[]{0x04};
    private static final byte[] USAGE_ID_COMMON_ECDH_RANDOM_DATA = new byte[]{0x19};
    private static final byte[] USAGE_ID_COMMON_DH_RANDOM_DATA = new byte[]{0x20};

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
    }

    /**
     * Close SharedSecret4 instance by securely clearing used memory that contains sensitive data.
     */
    @Override
    public void close() {
        clear(this.braceKey);
        clear(this.k);
        // FIXME securely clear other fields
    }

    /**
     * Derive initial shared secret from security parameters as they are received from the DAKE.
     *
     * @param params The security parameters.
     * @return Returns the initialized shared secrets instance.
     * @throws OtrCryptoException Throws in case of illegal values for shared secrets.
     */
    // FIXME review secure deletions as described by section "Interactive DAKE Overview".
    @Nonnull
    public static SharedSecret4 initialize(@Nonnull final SecurityParameters4 params) throws OtrCryptoException {
        final SharedSecret4 exchangeSecrets = new SharedSecret4(params.getDhKeyPair(), params.getEcdhKeyPair(),
            params.getA(), params.getX());
        final byte[] k = exchangeSecrets.getK();
        // Generate common shared secret using Bob's information stored in security parameters.
        final ECDHKeyPair initialECDHKeyPair;
        {
            final byte[] r = new byte[LENGTH_SECRET_KEY_BYTES + 1];
            kdf1(r, 1, concatenate(USAGE_ID_COMMON_ECDH_RANDOM_DATA, k), LENGTH_SECRET_KEY_BYTES);
            initialECDHKeyPair = ECDHKeyPair.generate(r);
        }
        // Generate common shared secret using Bob's information stored in security parameters.
        final DHKeyPair initialDHKeyPair;
        {
            final byte[] r = new byte[DH_PRIVATE_KEY_LENGTH_BYTES];
            kdf1(r, 0, concatenate(USAGE_ID_COMMON_DH_RANDOM_DATA, k), DH_PRIVATE_KEY_LENGTH_BYTES);
            initialDHKeyPair = DHKeyPair.generate(r);
        }
        switch (params.getInitializationComponent()) {
            case OURS:
                return new SharedSecret4(initialDHKeyPair, initialECDHKeyPair, params.getA(), params.getX());
            case THEIRS:
                return new SharedSecret4(params.getDhKeyPair(), params.getEcdhKeyPair(),
                    initialDHKeyPair.getPublicKey(), initialECDHKeyPair.getPublicKey());
            default:
                throw new UnsupportedOperationException("Unsupported component. Shared secret cannot be generated.");
        }
    }

    public Point getECDHPublicKey() {
        return this.ecdhKeyPair.getPublicKey();
    }

    public BigInteger getDHPublicKey() {
        return this.dhKeyPair.getPublicKey();
    }

    /**
     * Get mixed shared secret K.
     *
     * @return Mixed shared secret K.
     */
    public byte[] getK() {
        return this.k.clone();
    }

    /**
     * Rotate our key pairs in the shared secret.
     *
     * @param ratchetIteration The ratchet iteration a.k.a. 'i'.
     */
    // FIXME is a DHKeyPair always expected/required?
    public void rotateOurKeys(final int ratchetIteration, @Nonnull final ECDHKeyPair ourECDHKeyPair,
                       @Nullable final DHKeyPair ourDHKeyPair) {
        this.ecdhKeyPair = requireNonNull(ourECDHKeyPair);
        if (ratchetIteration % 3 == 0) {
            this.dhKeyPair = requireNonNull(ourDHKeyPair);
        }
        regenerateK(ratchetIteration);
    }

    /**
     * Rotate their public keys in the shared secret.
     *
     * @param ratchetIteration   The ratchet iteration a.k.a. 'i'.
     * @param theirECDHPublicKey Their ECDH public key.
     * @param theirDHPublicKey   Their DH public key.
     */
    public void rotateTheirKeys(final int ratchetIteration, @Nonnull final Point theirECDHPublicKey,
                         @Nullable final BigInteger theirDHPublicKey) {
        // FIXME verify requirements of public key before accepting it.
        this.theirECDHPublicKey = requireNonNull(theirECDHPublicKey);
        if (ratchetIteration % 3 == 0) {
            // FIXME we probably do not receive a new DH public key on every message. Hence we need to conditionally rotate DH public keys only on specific iterations.
            this.theirDHPublicKey = requireNonNull(theirDHPublicKey);
        }
        // FIXME securely delete our_ecdh.secret.
        regenerateK(ratchetIteration);
    }

    private void regenerateK(final int ratchetIteration) {
        final byte[] k_ecdh;
        try {
            k_ecdh = this.ecdhKeyPair.generateSharedSecret(this.theirECDHPublicKey).encode();
        } catch (final OtrCryptoException e) {
            throw new IllegalStateException("BUG: ECDH public keys should have been verified. No unexpected failures should happen at this point.", e);
        }
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
}
