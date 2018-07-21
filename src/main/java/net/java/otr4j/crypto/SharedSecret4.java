package net.java.otr4j.crypto;

import net.java.otr4j.session.ake.SecurityParameters4;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.DHKeyPair.DH_PRIVATE_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.ECDHKeyPair.SECRET_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.BRACE_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.DH_FIRST_EPHEMERAL;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.ECDH_FIRST_EPHEMERAL;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SHARED_SECRET;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SSID;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.THIRD_BRACE_KEY;
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

    private static final int SSID_LENGTH_BYTES = 8;
    private static final int BRACE_KEY_LENGTH_BYTES = 32;
    private static final int K_LENGTH_BYTES = 64;

    /**
     * SecureRandom instance.
     */
    private final SecureRandom random;

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
     * The serialized ECDH shared secret computed from an ECDH exchange, serialized as a
     * {@link nl.dannyvanheumen.joldilocks.Point}.
     */
    @Nonnull
    private ECDHKeyPair ecdhKeyPair;

    /**
     * The 3072-bit DH shared secret computed from a DH key exchange, serialized as a big-endian unsigned integer.
     */
    @Nonnull
    private DHKeyPair dhKeyPair;

    /**
     * Other party's ECDH public key.
     */
    private Point theirECDHPublicKey;

    /**
     * Other party's DH public key.
     */
    private BigInteger theirDHPublicKey;

    SharedSecret4(@Nonnull final SecureRandom random, @Nonnull final DHKeyPair ourDHKeyPair,
                  @Nonnull final ECDHKeyPair ourECDHKeyPair) {
        this.random = requireNonNull(random);
        this.ecdhKeyPair = requireNonNull(ourECDHKeyPair);
        this.dhKeyPair = requireNonNull(ourDHKeyPair);
        this.theirECDHPublicKey = null;
        this.theirDHPublicKey = null;
    }

    SharedSecret4(@Nonnull final SecureRandom random, @Nonnull final DHKeyPair ourDHKeyPair,
                          @Nonnull final ECDHKeyPair ourECDHKeyPair, @Nonnull final BigInteger theirDHPublicKey,
                          @Nonnull final Point theirECDHPublicKey) {
        this.random = requireNonNull(random);
        this.ecdhKeyPair = requireNonNull(ourECDHKeyPair);
        this.theirECDHPublicKey = requireNonNull(theirECDHPublicKey);
        this.dhKeyPair = requireNonNull(ourDHKeyPair);
        this.theirDHPublicKey = requireNonNull(theirDHPublicKey);
        regenerateK(true);
    }

    /**
     * Close SharedSecret4 instance by securely clearing used memory that contains sensitive data.
     */
    @Override
    public void close() {
        // FIXME consider adding nulling public keys to prevent further use.
        clear(this.braceKey);
        clear(this.k);
        // FIXME securely clear other fields
    }

    @Nonnull
    public static byte[] generateSSID(@Nonnull final SecureRandom random, @Nonnull final SecurityParameters4 params) {
        try (SharedSecret4 exchangeSecrets = new SharedSecret4(random, params.getDhKeyPair(),
            params.getEcdhKeyPair(), params.getA(), params.getX())) {
            return kdf1(SSID, exchangeSecrets.getK(), SSID_LENGTH_BYTES);
        }
    }

    @Nonnull
    public static byte[] generateK(@Nonnull final SecureRandom random, @Nonnull final SecurityParameters4 params) {
        final SharedSecret4 sharedSecret = new SharedSecret4(random, params.getDhKeyPair(), params.getEcdhKeyPair(),
            params.getA(), params.getX());
        return sharedSecret.getK();
    }

    /**
     * Derive initial shared secret from security parameters as they are received from the DAKE.
     *
     * @param params The security parameters.
     * @return Returns the initialized shared secrets instance.
     */
    // FIXME review secure deletions as described by section "Interactive DAKE Overview".
    @Nonnull
    public static SharedSecret4 initialize(@Nonnull final SecureRandom random, @Nonnull final SecurityParameters4 params) {
        final SharedSecret4 exchangeSecrets = new SharedSecret4(random, params.getDhKeyPair(), params.getEcdhKeyPair(),
            params.getA(), params.getX());
        final byte[] k = exchangeSecrets.getK();
        // Generate common shared secret using Bob's information stored in security parameters.
        final ECDHKeyPair initialECDHKeyPair;
        {
            final byte[] r = new byte[SECRET_KEY_LENGTH_BYTES];
            kdf1(r, 0, ECDH_FIRST_EPHEMERAL, k, SECRET_KEY_LENGTH_BYTES);
            initialECDHKeyPair = ECDHKeyPair.generate(r);
        }
        // Generate common shared secret using Bob's information stored in security parameters.
        final DHKeyPair initialDHKeyPair;
        {
            final byte[] r = new byte[DH_PRIVATE_KEY_LENGTH_BYTES];
            kdf1(r, 0, DH_FIRST_EPHEMERAL, k, DH_PRIVATE_KEY_LENGTH_BYTES);
            initialDHKeyPair = DHKeyPair.generate(r);
        }
        switch (params.getInitializationComponent()) {
            case OURS:
                return new SharedSecret4(random, initialDHKeyPair, initialECDHKeyPair);
            case THEIRS:
                return new SharedSecret4(random, params.getDhKeyPair(), params.getEcdhKeyPair(),
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
        requireInitializationCompleted();
        return this.k.clone();
    }

    /**
     * Rotate our key pairs in the shared secret.
     *
     * @param regenerateDHKeyPair Indicates whether we need to regenerate the DH key pair as well.
     */
    public void rotateOurKeys(final boolean regenerateDHKeyPair) {
        requireInitializationCompleted();
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(this.random);
        this.ecdhKeyPair = requireNonNull(ourECDHKeyPair);
        if (regenerateDHKeyPair) {
            final DHKeyPair ourDHKeyPair = DHKeyPair.generate(this.random);
            this.dhKeyPair = requireNonNull(ourDHKeyPair);
        }
        regenerateK(regenerateDHKeyPair);
    }

    /**
     * Rotate their public keys in the shared secret.
     *
     * @param performDHRatchet   Indicates whether we need to perform a DH ratchet.
     * @param theirECDHPublicKey Their ECDH public key.
     * @param theirDHPublicKey   Their DH public key. (Optional)
     */
    public void rotateTheirKeys(final boolean performDHRatchet, @Nonnull final Point theirECDHPublicKey,
                         @Nullable final BigInteger theirDHPublicKey) {
        // FIXME verify requirements of public key before accepting it.
        this.theirECDHPublicKey = requireNonNull(theirECDHPublicKey);
        if (performDHRatchet) {
            // FIXME we probably do not receive a new DH public key on every message. Hence we need to conditionally rotate DH public keys only on specific iterations.
            this.theirDHPublicKey = requireNonNull(theirDHPublicKey);
        }
        // FIXME securely delete our_ecdh.secret.
        regenerateK(performDHRatchet);
    }

    private void regenerateK(final boolean performDHRatchet) {
        requireInitializationCompleted();
        final byte[] k_ecdh;
        try {
            k_ecdh = this.ecdhKeyPair.generateSharedSecret(this.theirECDHPublicKey).encode();
        } catch (final OtrCryptoException e) {
            throw new IllegalStateException("BUG: ECDH public keys should have been verified. No unexpected failures should happen at this point.", e);
        }
        if (performDHRatchet) {
            final byte[] k_dh = asUnsignedByteArray(this.dhKeyPair.generateSharedSecret(this.theirDHPublicKey));
            kdf1(this.braceKey, 0, THIRD_BRACE_KEY, k_dh, BRACE_KEY_LENGTH_BYTES);
            clear(k_dh);
            // FIXME securely delete our_dh.secret.
        } else {
            kdf1(this.braceKey, 0, BRACE_KEY, this.braceKey, BRACE_KEY_LENGTH_BYTES);
        }
        kdf1(this.k, 0, SHARED_SECRET, concatenate(k_ecdh, this.braceKey), K_LENGTH_BYTES);
        clear(k_ecdh);
    }

    private void requireInitializationCompleted() {
        if (this.theirECDHPublicKey == null || this.theirDHPublicKey == null) {
            throw new IllegalStateException("Shared secrets have not been fully initialized. Other party's public keys need to be rotated first.");
        }
    }
}
