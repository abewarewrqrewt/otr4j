package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.concatenate;

// FIXME consider modifying the code such that this.rootKey is initialized with k_mixed. That way we can simplify the rest of the logic in the class.
final class DoubleRatchet {

    private static final int ROOT_KEY_LENGTH_BYTES = 64;
    private static final int CHAIN_KEY_LENGTH_BYTES = 64;

    private static final byte[] USAGE_ID_ROOT_KEY = new byte[]{0x21};
    private static final byte[] USAGE_ID_CHAIN_KEY = new byte[]{0x22};

    private final SharedSecret4 sharedSecret;

    private final byte[] rootKey = new byte[ROOT_KEY_LENGTH_BYTES];

    private final byte[] sendingChainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

    private final byte[] receivingChainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

    /**
     * The ratchet ID.
     */
    // FIXME when should i be incremented?
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

    DoubleRatchet(@Nonnull final SharedSecret4 sharedSecret) {
        this.sharedSecret = requireNonNull(sharedSecret);
    }

    /**
     * Rotate the sender key.
     */
    void rotateSenderKey() throws OtrCryptoException {
        this.j = 0;
        // FIXME verify that i is still correct, should it be incremented first? (Nothing is mentioned in the sender rotation spec.)
        final byte[] previousRootKey = this.i == 0 ? this.sharedSecret.getK() : this.rootKey.clone();
        this.sharedSecret.rotateOurKeys(this.i);
        final byte[] newK = this.sharedSecret.getK();
        kdf1(this.rootKey, 0, concatenate(USAGE_ID_ROOT_KEY, previousRootKey, newK), ROOT_KEY_LENGTH_BYTES);
        kdf1(this.sendingChainKey, 0, concatenate(USAGE_ID_CHAIN_KEY, previousRootKey, newK),
            CHAIN_KEY_LENGTH_BYTES);
        clear(previousRootKey);
        clear(newK);
    }

    /**
     * Rotate the receiver key.
     *
     * @param otherDH   The other party's DH public key.
     * @param otherECDH The other party's ECDH public key.
     */
    void rotateReceiverKey(@Nonnull final BigInteger otherDH, @Nonnull final Point otherECDH) throws OtrCryptoException {
        this.k = 0;
        // FIXME verify that i is still correct, should it be incremented first? (Nothing is mentioned in the sender rotation spec.)
        this.sharedSecret.rotateTheirKeys(this.i, otherECDH, otherDH);
        final byte[] newK = this.sharedSecret.getK();
        kdf1(this.rootKey, 0, concatenate(USAGE_ID_ROOT_KEY, this.rootKey, newK), ROOT_KEY_LENGTH_BYTES);
        kdf1(this.receivingChainKey, 0, concatenate(USAGE_ID_CHAIN_KEY, this.rootKey, newK),
            CHAIN_KEY_LENGTH_BYTES);
        clear(newK);
    }

    // FIXME consider removing the generate method and moving key generation to the rotate method.
    MessageKeys generateSendingKeys() {
        return MessageKeys.generate(this.sendingChainKey);
    }

    // FIXME consider removing the generate method and moving key generation to the rotate method.
    MessageKeys generateReceivingKeys() {
        return MessageKeys.generate(this.receivingChainKey);
    }

    /**
     * Encryption and MAC keys derived from chain key.
     */
    // TODO should we clear the fields at some point due to them containing sensitive material?
    static final class MessageKeys {

        private static final byte[] USAGE_ID_ENC = new byte[]{0x24};
        private static final byte[] USAGE_ID_MAC = new byte[]{0x25};

        private static final int MK_ENC_LENGTH_BYTES = 32;
        private static final int MK_MAC_LENGTH_BYTES = 64;

        private final byte[] encrypt;
        private final byte[] mac;

        /**
         * Construct Keys instance.
         *
         * @param mkEnc message key for encryption
         * @param mkMac message key for message authentication
         */
        private MessageKeys(@Nonnull final byte[] mkEnc, @Nonnull final byte[] mkMac) {
            this.encrypt = requireLengthExactly(MK_ENC_LENGTH_BYTES, mkEnc);
            this.mac = requireLengthExactly(MK_MAC_LENGTH_BYTES, mkMac);
        }

        /**
         * Generate a Keys instance using provided chain key.
         *
         * @param chainKey The chain key
         * @return Returns a Keys instance containing generated keys.
         */
        @Nonnull
        static MessageKeys generate(@Nonnull final byte[] chainKey) {
            final byte[] encrypt = new byte[MK_ENC_LENGTH_BYTES];
            kdf1(encrypt, 0, concatenate(USAGE_ID_ENC, chainKey), MK_ENC_LENGTH_BYTES);
            final byte[] mac = new byte[MK_MAC_LENGTH_BYTES];
            kdf1(mac, 0, concatenate(USAGE_ID_MAC, encrypt), MK_MAC_LENGTH_BYTES);
            return new MessageKeys(encrypt, mac);
        }
    }
}
