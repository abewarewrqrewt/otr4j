package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * The Shared Secret mechanism used in OTRv4.
 */
// TODO consider what we would need to do to reuse the same memory more. Right now we replace one reference by another, but we rely on the instances being cleaned up by the GC.
public final class SharedSecret4 {

    private static final int MK_ENC_LENGTH_BYTES = 32;
    private static final int MK_MAC_LENGTH_BYTES = 64;
    private static final int BRACE_KEY_LENGTH_BYTES = 32;
    private static final int K_LENGTH_BYTES = 64;

    private static final byte[] USAGE_ID_BRACE_KEY_FROM_DH = new byte[]{0x02};
    private static final byte[] USAGE_ID_BRACE_KEY_FROM_BRACE_KEY = new byte[]{0x03};
    private static final byte[] USAGE_ID_ENC = new byte[]{0x24};
    private static final byte[] USAGE_ID_MAC = new byte[]{0x25};

    /**
     * Secure random source.
     */
    private final SecureRandom random;

    /**
     * The 3072-bit DH shared secret computed from a DH key exchange, serialized as a big-endian unsigned integer.
     */
    private DHKeyPair dhKeyPair;

    /**
     * Shared key by DH key exchange.
     */
    private byte[] k_dh;

    /**
     * The serialized ECDH shared secret computed from an ECDH exchange, serialized as a
     * {@link nl.dannyvanheumen.joldilocks.Point}.
     */
    private ECDHKeyPair ecdhKeyPair;

    /**
     * Shared key by ECDH key exchange.
     */
    private byte[] k_ecdh;

    /**
     * Either a hash of the shared DH key: 'KDF_1(0x02 || k_dh, 32)' (every third DH ratchet) or a hash of the previous
     * 'brace_key: KDF_1(0x03 || brace_key, 32)'.
     */
    private final byte[] braceKey = new byte[BRACE_KEY_LENGTH_BYTES];

    /**
     * The Mixed shared secret is the final shared secret derived from both the brace key and ECDH shared secrets:
     * 'KDF_1(0x04 || K_ecdh || brace_key, 64)'.
     */
//    private final byte[] k = new byte[K_LENGTH_BYTES];

    /**
     * The ratchet ID.
     */
    private int i = 0;

    /**
     * The sending message ID.
     */
    private int j = 0;

    /**
     * The receiver message ID.
     */
    private int k = 0;

    /**
     * The number of messages in the previous ratchet.
     */
    private int pn = 0;

    private SharedSecret4(@Nonnull final SecureRandom random, @Nonnull final DHKeyPair dh, @Nonnull final ECDHKeyPair ecdh) {
        this.random = requireNonNull(random);
        this.dhKeyPair = requireNonNull(dh);
        this.k_dh = null;
        this.ecdhKeyPair = requireNonNull(ecdh);
        this.k_ecdh = null;
    }

    /**
     * Rotate the sender key.
     *
     * @param otherDH   The other party's DH public key.
     * @param otherECDH The other party's ECDH public key.
     */
    public void rotateSenderKey(@Nonnull final BigInteger otherDH, @Nonnull final Point otherECDH) throws OtrCryptoException {
        this.j = 0;
        this.ecdhKeyPair = ECDHKeyPair.generate(this.random);
        this.k_ecdh = this.ecdhKeyPair.generateSharedSecret(otherECDH).encode();
        if (i % 3 == 0) {
            // "Generate the new DH key pair and assign it to our_dh = generateDH() (by securely replacing the old
            // value)."
            this.dhKeyPair = DHKeyPair.generate(this.random);
            // "Calculate k_dh = DH(our_dh.secret, their_dh)."
            this.k_dh = asUnsignedByteArray(this.dhKeyPair.generateSharedSecret(otherDH));
            // "Calculate a brace_key = KDF_1(0x02 || k_dh, 32)."
            kdf1(this.braceKey, 0, concatenate(USAGE_ID_BRACE_KEY_FROM_DH, this.k_dh), BRACE_KEY_LENGTH_BYTES);
        } else {
            // "Derive and securely overwrite brace_key = KDF_1(0x03 || brace_key, 32)."
            kdf1(this.braceKey, 0, concatenate(USAGE_ID_BRACE_KEY_FROM_BRACE_KEY, this.braceKey),
                BRACE_KEY_LENGTH_BYTES);
        }
        // FIXME need to do root key derivation now?
    }

    /**
     * Rotate the receiver key.
     *
     * @param otherDH   The other party's DH public key.
     * @param otherECDH The other party's ECDH public key.
     */
    public void rotateReceiverKey(@Nonnull final BigInteger otherDH, @Nonnull final Point otherECDH) throws OtrCryptoException {
        this.k = 0;
        this.k_ecdh = this.ecdhKeyPair.generateSharedSecret(otherECDH).encode();
        // FIXME need to securely delete our ECDH secret key as we do not need it anymore.
        if (i % 3 == 0) {
            // "Retrieve the DH key ('Public DH key') from the received data message and assign it to their_dh."
            // "Calculate k_dh = DH(our_dh.secret, their_dh)."
            this.k_dh = asUnsignedByteArray(this.dhKeyPair.generateSharedSecret(otherDH));
            // "Calculate a brace_key = KDF_1(0x02 || k_dh, 32)."
            kdf1(this.braceKey, 0, concatenate(new byte[]{0x02}, this.k_dh), BRACE_KEY_LENGTH_BYTES);
            // "Securely delete our_dh.secret and k_dh."
            // FIXME need to securely delete our_dh.secret and k_dh.

        } else {
            // "Derive and securely overwrite brace_key = KDF_1(0x03 || brace_key, 32)."
            kdf1(this.braceKey, 0, concatenate(new byte[]{0x03}, this.braceKey), BRACE_KEY_LENGTH_BYTES);
        }
        // FIXME need to do root key derivation now?
    }

    /**
     * Encryption and MAC keys derived from chain key.
     */
    // TODO should we clear the fields at some point due to them containing sensitive material?
    private static final class Keys {

        private final byte[] mkEnc;
        private final byte[] mkMac;

        /**
         * Construct Keys instance.
         *
         * @param mkEnc message key for encryption
         * @param mkMac message key for message authentication
         */
        private Keys(@Nonnull final byte[] mkEnc, @Nonnull final byte[] mkMac) {
            this.mkEnc= requireLengthExactly(MK_ENC_LENGTH_BYTES, mkEnc);
            this.mkMac = requireLengthExactly(MK_MAC_LENGTH_BYTES, mkMac);
        }

        /**
         * Generate a Keys instance using provided chain key.
         *
         * @param chainKey The chain key
         * @return Returns a Keys instance containing generated keys.
         */
        @Nonnull
        static Keys generate(@Nonnull final byte[] chainKey) {
            final byte[] mkEnc = new byte[MK_ENC_LENGTH_BYTES];
            kdf1(mkEnc, 0, concatenate(USAGE_ID_ENC, chainKey), MK_ENC_LENGTH_BYTES);
            final byte[] mkMac = new byte[MK_MAC_LENGTH_BYTES];
            kdf1(mkMac, 0, concatenate(USAGE_ID_MAC, mkEnc), MK_MAC_LENGTH_BYTES);
            return new Keys(mkEnc, mkMac);
        }
    }
}
