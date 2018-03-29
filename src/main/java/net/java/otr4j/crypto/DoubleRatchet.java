package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.concatenate;

// TODO DoubleRatchet currently does not keep history. Therefore it is not possible to decode out-of-order messages from previous ratchets.
// TODO Currently we do not keep track of used MACs for later reveal.
final class DoubleRatchet {

    private static final int SSID_LENGTH_BYTES = 8;
    private static final int ROOT_KEY_LENGTH_BYTES = 64;
    private static final int CHAIN_KEY_LENGTH_BYTES = 64;

    private static final byte[] USAGE_ID_SSID_GENERATION = new byte[]{0x05};
    private static final byte[] USAGE_ID_ROOT_KEY = new byte[]{0x21};
    private static final byte[] USAGE_ID_CHAIN_KEY = new byte[]{0x22};

    private final SecureRandom random;

    private final SharedSecret4 sharedSecret;

    private final byte[] rootKey = new byte[ROOT_KEY_LENGTH_BYTES];

    private final byte[] sendingChainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

    private final byte[] receivingChainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

    /**
     * The ratchet ID.
     */
    // FIXME when should i be incremented? (On every rotation?)
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

    DoubleRatchet(@Nonnull final SecureRandom random, @Nonnull final SharedSecret4 sharedSecret) {
        this.random = requireNonNull(random);
        this.sharedSecret = requireNonNull(sharedSecret);
    }

    /**
     * Rotate the sender key.
     */
    void rotateSenderKeys() throws OtrCryptoException {
        this.j = 0;
        // FIXME verify that i is still correct, should it be incremented first? (Nothing is mentioned in the sender rotation spec.)
        final byte[] previousRootKey = derivePreviousRootKey();
        this.sharedSecret.rotateOurKeys(this.i, ECDHKeyPair.generate(this.random), DHKeyPair.generate(this.random));
        final byte[] newK = this.sharedSecret.getK();
        kdf1(this.rootKey, 0, concatenate(USAGE_ID_ROOT_KEY, previousRootKey, newK), ROOT_KEY_LENGTH_BYTES);
        kdf1(this.sendingChainKey, 0, concatenate(USAGE_ID_CHAIN_KEY, previousRootKey, newK),
            CHAIN_KEY_LENGTH_BYTES);
        clear(newK);
        clear(previousRootKey);
    }

    /**
     * Rotate the receiver key.
     *
     * @param otherDH   The other party's DH public key.
     * @param otherECDH The other party's ECDH public key.
     */
    void rotateReceiverKeys(@Nonnull final BigInteger otherDH, @Nonnull final Point otherECDH) throws OtrCryptoException {
        this.k = 0;
        // FIXME verify that i is still correct, should it be incremented first? (Nothing is mentioned in the sender rotation spec.)
        final byte[] previousRootKey = derivePreviousRootKey();
        this.sharedSecret.rotateTheirKeys(this.i, otherECDH, otherDH);
        final byte[] newK = this.sharedSecret.getK();
        kdf1(this.rootKey, 0, concatenate(USAGE_ID_ROOT_KEY, previousRootKey, newK), ROOT_KEY_LENGTH_BYTES);
        kdf1(this.receivingChainKey, 0, concatenate(USAGE_ID_CHAIN_KEY, previousRootKey, newK),
            CHAIN_KEY_LENGTH_BYTES);
        clear(newK);
        clear(previousRootKey);
    }

    private byte[] derivePreviousRootKey() {
        return this.i == 0 ? this.sharedSecret.getK() : this.rootKey.clone();
    }

    byte[] generateSSID() {
        final byte[] ssid = new byte[SSID_LENGTH_BYTES];
        kdf1(ssid, 0, concatenate(USAGE_ID_SSID_GENERATION, this.sharedSecret.getK()), SSID_LENGTH_BYTES);
        return ssid;
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
    // TODO consider delaying calculation of extra symmetric key (and possibly mkEnc and mkMac) to reduce the number of calculations.
    // TODO should we clear the fields at some point due to them containing sensitive material?
    static final class MessageKeys {

        private static final byte[] USAGE_ID_ENC = new byte[]{0x24};
        private static final byte[] USAGE_ID_MAC = new byte[]{0x25};
        private static final byte[] USAGE_ID_EXTRA_SYMMETRIC_KEY = new byte[]{0x26, (byte) 0xff};

        private static final int MK_ENC_LENGTH_BYTES = 32;
        private static final int MK_MAC_LENGTH_BYTES = 64;
        private static final int EXTRA_SYMMETRIC_KEY_LENGTH_BYTES = 32;

        private final byte[] encrypt;
        private final byte[] mac;
        private final byte[] extraSymmetricKey;

        /**
         * Construct Keys instance.
         *
         * @param encrypt           message key for encryption
         * @param mac               message key for message authentication
         * @param extraSymmetricKey extra symmetric key
         */
        private MessageKeys(@Nonnull final byte[] encrypt, @Nonnull final byte[] mac,
                            @Nonnull final byte[] extraSymmetricKey) {
            this.encrypt = requireLengthExactly(MK_ENC_LENGTH_BYTES, encrypt);
            this.mac = requireLengthExactly(MK_MAC_LENGTH_BYTES, mac);
            this.extraSymmetricKey = requireLengthExactly(EXTRA_SYMMETRIC_KEY_LENGTH_BYTES, extraSymmetricKey);
        }

        /**
         * Generate a Keys instance using provided chain key.
         *
         * @param chainKey The chain key
         * @return Returns a Keys instance containing generated keys.
         */
        @Nonnull
        private static MessageKeys generate(@Nonnull final byte[] chainKey) {
            final byte[] encrypt = new byte[MK_ENC_LENGTH_BYTES];
            kdf1(encrypt, 0, concatenate(USAGE_ID_ENC, chainKey), MK_ENC_LENGTH_BYTES);
            final byte[] mac = new byte[MK_MAC_LENGTH_BYTES];
            kdf1(mac, 0, concatenate(USAGE_ID_MAC, encrypt), MK_MAC_LENGTH_BYTES);
            final byte[] extraSymmetricKey = new byte[EXTRA_SYMMETRIC_KEY_LENGTH_BYTES];
            kdf1(extraSymmetricKey, 0, concatenate(USAGE_ID_EXTRA_SYMMETRIC_KEY, chainKey),
                EXTRA_SYMMETRIC_KEY_LENGTH_BYTES);
            return new MessageKeys(encrypt, mac, extraSymmetricKey);
        }

        @Nonnull
        byte[] getEncrypt() {
            return encrypt;
        }

        @Nonnull
        byte[] getMac() {
            return mac;
        }

        @Nonnull
        byte[] getExtraSymmetricKey() {
            return extraSymmetricKey;
        }
    }
}
