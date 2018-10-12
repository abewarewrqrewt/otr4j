package net.java.otr4j.crypto;

import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.ValidationException;
import net.java.otr4j.session.ake.SecurityParameters4;
import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Point;
import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.DHKeyPair.DH_PRIVATE_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.DHKeyPair.checkPublicKey;
import static net.java.otr4j.crypto.ed448.ECDHKeyPair.SECRET_KEY_LENGTH_BYTES;
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
 * The Shared Secret-mechanism used in OTRv4.
 */
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
    private ECDHKeyPair ecdhKeyPair;

    /**
     * The 3072-bit DH shared secret computed from a DH key exchange, serialized as a big-endian unsigned integer.
     */
    private DHKeyPair dhKeyPair;

    /**
     * Other party's ECDH public key.
     */
    private Point theirECDHPublicKey;

    /**
     * Other party's DH public key.
     */
    private BigInteger theirDHPublicKey;

    SharedSecret4(@Nonnull final SecureRandom random, @Nullable final DHKeyPair ourDHKeyPair,
            @Nullable final ECDHKeyPair ourECDHKeyPair, @Nullable final BigInteger theirDHPublicKey,
            @Nullable final Point theirECDHPublicKey) {
        this.random = requireNonNull(random);
        if ((ourECDHKeyPair == null || ourDHKeyPair == null) && (theirECDHPublicKey == null || theirDHPublicKey == null)) {
            throw new IllegalArgumentException("Expected either local key pairs or remote public keys to be provided. We cannot leave everything null at initialization time.");
        }
        this.ecdhKeyPair = ourECDHKeyPair;
        this.theirECDHPublicKey = theirECDHPublicKey;
        this.dhKeyPair = ourDHKeyPair;
        this.theirDHPublicKey = theirDHPublicKey;
        if (this.ecdhKeyPair != null && this.dhKeyPair != null && this.theirECDHPublicKey != null && this.theirDHPublicKey != null) {
            regenerateK(Rotation.SENDER_KEYS, true);
        }
    }

    /**
     * Close SharedSecret4 instance by securely clearing used memory that contains sensitive data.
     */
    @Override
    public void close() {
        clear(this.braceKey);
        clear(this.k);
        this.ecdhKeyPair.close();
        this.dhKeyPair.close();
    }

    /**
     * Create shared secret based on security parameters established during the key exchange.
     *
     * @param random SecureRandom instance
     * @param params established security parameters
     * @return Returns SharedSecret4 instance.
     */
    public static SharedSecret4 createSharedSecret(@Nonnull final SecureRandom random, @Nonnull final SecurityParameters4 params) {
        return new SharedSecret4(random, requireNonNull(params.getDhKeyPair()), requireNonNull(params.getEcdhKeyPair()),
            requireNonNull(params.getA()), requireNonNull(params.getX()));
    }

    /**
     * Prepare initial SharedSecret4 instance.
     *
     * @param random                  SecureRandom instance
     * @param k                       mixed shared secret 'K'
     * @param initializationComponent Indicator for which part of the cryptographic material should be initialized.
     * @return Returns the initialized shared secrets instance.
     */
    @Nonnull
    public static SharedSecret4 initialize(@Nonnull final SecureRandom random, @Nonnull final byte[] k,
            @Nonnull final SecurityParameters4.Component initializationComponent) {
        final ECDHKeyPair initialECDHKeyPair = ECDHKeyPair.generate(kdf1(ECDH_FIRST_EPHEMERAL, k, SECRET_KEY_LENGTH_BYTES));
        final DHKeyPair initialDHKeyPair = DHKeyPair.generate(kdf1(DH_FIRST_EPHEMERAL, k, DH_PRIVATE_KEY_LENGTH_BYTES));
        switch (initializationComponent) {
        case OURS:
            // Bob initializes his shared secrets for the Double Ratchet, although it is still missing Alice's keys.
            return new SharedSecret4(random, initialDHKeyPair, initialECDHKeyPair, null, null);
        case THEIRS:
            // Alice initializes her shared secrets for the Double Ratchet with Bob's deterministic ECDH and DH key pairs.
            initialECDHKeyPair.close();
            initialDHKeyPair.close();
            return new SharedSecret4(random, null, null, initialDHKeyPair.getPublicKey(),
                initialECDHKeyPair.getPublicKey());
        default:
            throw new UnsupportedOperationException("Unsupported component. Shared secret cannot be generated.");
        }
    }

    /**
     * Get ephemeral ECDH public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getECDHPublicKey() {
        return this.ecdhKeyPair.getPublicKey();
    }

    /**
     * Get ephemeral DH public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public BigInteger getDHPublicKey() {
        return this.dhKeyPair.getPublicKey();
    }

    /**
     * Get "their" (remote) ECDH public key.
     *
     * @return Returns the public key.
     */
    @Nullable
    public Point getTheirECDHPublicKey() {
        return theirECDHPublicKey;
    }

    /**
     * Get "their" (remote) DH public key.
     *
     * @return Returns the public key.
     */
    @Nullable
    public BigInteger getTheirDHPublicKey() {
        return theirDHPublicKey;
    }

    /**
     * Get mixed shared secret K.
     *
     * @return Mixed shared secret K.
     */
    @Nonnull
    public byte[] getK() {
        requireInitializationCompleted();
        return this.k.clone();
    }

    /**
     * Generate SSID.
     * <p>
     * NOTE: the only relevant SSID value is the one that is generated from the initial DAKE security parameters.
     * If you call this method at any later time, check if you are sure that you want *this* value or the initial SSID.
     *
     * @return Returns the SSID.
     */
    @Nonnull
    public byte[] generateSSID() {
        requireInitializationCompleted();
        return kdf1(SSID, this.k, SSID_LENGTH_BYTES);
    }

    /**
     * Rotate our key pairs in the shared secret.
     *
     * @param regenerateDHKeyPair Indicates whether we need to regenerate the DH key pair as well.
     */
    public void rotateOurKeys(final boolean regenerateDHKeyPair) {
        if (this.theirECDHPublicKey == null || this.theirDHPublicKey == null) {
            throw new IllegalStateException("To rotate our key pairs, it is required that other party's public keys are available.");
        }
        this.ecdhKeyPair = ECDHKeyPair.generate(this.random);
        if (regenerateDHKeyPair) {
            this.dhKeyPair = DHKeyPair.generate(this.random);
        }
        regenerateK(Rotation.SENDER_KEYS, regenerateDHKeyPair);
    }

    /**
     * Rotate their public keys in the shared secret.
     *
     * @param performDHRatchet   Indicates whether we need to perform a DH ratchet.
     * @param theirECDHPublicKey Their ECDH public key.
     * @param theirDHPublicKey   Their DH public key. (Optional)
     * @throws OtrCryptoException In case of failure to rotate the public keys.
     */
    // FIXME need to verify that public keys (ECDH and DH) were not encountered previously.
    public void rotateTheirKeys(final boolean performDHRatchet, @Nonnull final Point theirECDHPublicKey,
            @Nullable final BigInteger theirDHPublicKey) throws OtrCryptoException {
        if (this.ecdhKeyPair == null || this.dhKeyPair == null) {
            throw new IllegalStateException("To rotate other party's public keys, it is required that our own keys are available.");
        }
        if (!Ed448.contains(requireNonNull(theirECDHPublicKey))) {
            throw new OtrCryptoException("ECDH public key failed verification.");
        }
        if (Points.equals(this.ecdhKeyPair.getPublicKey(), theirECDHPublicKey)) {
            throw new OtrCryptoException("A new, different ECDH public key is expected for initializing the new ratchet.");
        }
        if (this.dhKeyPair.getPublicKey().equals(theirDHPublicKey)) {
            throw new OtrCryptoException("A new, different DH public key is expected for initializing the new ratchet.");
        }
        this.theirECDHPublicKey = theirECDHPublicKey;
        if (performDHRatchet) {
            if (!checkPublicKey(requireNonNull(theirDHPublicKey))) {
                throw new OtrCryptoException("DH public key failed verification.");
            }
            this.theirDHPublicKey = theirDHPublicKey;
        }
        regenerateK(Rotation.RECEIVER_KEYS, performDHRatchet);
        this.ecdhKeyPair.close();
    }

    @SuppressWarnings("PMD.LocalVariableNamingConventions")
    private void regenerateK(final Rotation rotation, final boolean performDHRatchet) {
        requireInitializationCompleted();
        final byte[] k_ecdh;
        try {
            k_ecdh = this.ecdhKeyPair.generateSharedSecret(this.theirECDHPublicKey).encode();
        } catch (final ValidationException e) {
            throw new IllegalStateException("BUG: ECDH public keys should have been verified. No unexpected failures should happen at this point.", e);
        }
        if (performDHRatchet) {
            final byte[] k_dh = asUnsignedByteArray(this.dhKeyPair.generateSharedSecret(this.theirDHPublicKey));
            kdf1(this.braceKey, 0, THIRD_BRACE_KEY, k_dh, BRACE_KEY_LENGTH_BYTES);
            clear(k_dh);
            if (rotation == Rotation.RECEIVER_KEYS) {
                this.dhKeyPair.close();
            }
        } else {
            kdf1(this.braceKey, 0, BRACE_KEY, this.braceKey, BRACE_KEY_LENGTH_BYTES);
        }
        final byte[] tempKecdhBraceKey = concatenate(k_ecdh, this.braceKey);
        kdf1(this.k, 0, SHARED_SECRET, tempKecdhBraceKey, K_LENGTH_BYTES);
        clear(tempKecdhBraceKey);
        clear(k_ecdh);
    }

    private void requireInitializationCompleted() {
        if (this.ecdhKeyPair == null || this.dhKeyPair == null || this.theirECDHPublicKey == null || this.theirDHPublicKey == null) {
            throw new IllegalStateException("Shared secrets have not been fully initialized. Other party's public keys need to be rotated first.");
        }
    }

    private enum Rotation {
        SENDER_KEYS, RECEIVER_KEYS
    }
}
