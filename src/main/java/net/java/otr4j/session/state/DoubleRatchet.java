package net.java.otr4j.session.state;

import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.SharedSecret4;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTHENTICATOR;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.EXTRA_SYMMETRIC_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.MAC_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.MESSAGE_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.NEXT_CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateNonce;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.concatenate;

// TODO DoubleRatchet currently does not keep history. Therefore it is not possible to decode out-of-order messages from previous ratchets. (Also needed to keep MessageKeys instances for messages failing verification.)
// TODO Currently we do not keep track of used MACs for later reveal.
// FIXME need to clean up DoubleRatchet after use. (Zero memory containing secrets.)
// TODO consider adding a counter/semaphore in order to verify that "at most one" (depending on circumstances) set of message keys is active at a time. Ensures that message keys are appropriately cleaned after use.
// FIXME closing ratchet should also close any remaining message keys
// FIXME finish writing unit tests after ratchet implementation is finished.
// TODO is it possible to use the same Chain Key for more than 1 message?
final class DoubleRatchet implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DoubleRatchet.class.getName());

    private static final int ROOT_KEY_LENGTH_BYTES = 64;
    private static final int CHAIN_KEY_LENGTH_BYTES = 64;

    private final SecureRandom random;

    private final SharedSecret4 sharedSecret;

    private final byte[] rootKey = new byte[ROOT_KEY_LENGTH_BYTES];

    private final byte[] sendingChainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

    private final byte[] receivingChainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

    // FIXME check if we can perform the rotations without needing an extra flag to indicate the status of the ratchet.
    private boolean needSenderKeyRotation = true;

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

    DoubleRatchet(@Nonnull final SecureRandom random, @Nonnull final SharedSecret4 sharedSecret) {
        this.random = requireNonNull(random);
        this.sharedSecret = requireNonNull(sharedSecret);
    }

    @Override
    public void close() {
        clear(this.rootKey);
        clear(this.receivingChainKey);
        clear(this.sendingChainKey);
        this.i = -1;
        this.j = 0;
        this.k = 0;
        this.pn = 0;
        this.sharedSecret.close();
    }

    boolean isNeedSenderKeyRotation() {
        return needSenderKeyRotation;
    }

    int getI() {
        return i;
    }

    int getJ() {
        return j;
    }

    int getK() {
        return k;
    }

    int getPn() {
        return pn;
    }

    @Nonnull
    Point getECDHPublicKey() {
        return this.sharedSecret.getECDHPublicKey();
    }

    @Nonnull
    BigInteger getDHPublicKey() {
        return this.sharedSecret.getDHPublicKey();
    }

    // TODO is there ever a reason to generate something other than the *current* sending keys?
    @Nonnull
    MessageKeys generateSendingKeys() {
        requireNotClosed();
        if (this.needSenderKeyRotation) {
            throw new IllegalStateException("Key rotation needs to be performed before new sending keys can be generated.");
        }
        LOGGER.log(Level.FINEST, "Generating sending message keys for ratchet " + (this.i - 1) + ", message " + this.j);
        final MessageKeys keys = MessageKeys.generate(this.random, this.i - 1, this.j, this.sendingChainKey);
        kdf1(this.sendingChainKey, 0, NEXT_CHAIN_KEY, this.sendingChainKey, CHAIN_KEY_LENGTH_BYTES);
        this.j += 1;
        return keys;
    }

    /**
     * Rotate the sender key.
     */
    // FIXME test rotateSenderKeys and verify interaction with rotate.
    @Nonnull
    Rotation rotateSenderKeys() {
        requireNotClosed();
        if (!this.needSenderKeyRotation) {
            throw new IllegalStateException("Rotation is only allowed after new public key material was received from the other party.");
        }
        LOGGER.log(Level.FINEST, "Rotating root key and sending chain key for ratchet " + this.i);
        this.j = 0;
        final byte[] previousRootKey = derivePreviousRootKey();
        final boolean performDHRatchet = this.i % 3 == 0;
        this.sharedSecret.rotateOurKeys(performDHRatchet);
        final byte[] newK = this.sharedSecret.getK();
        kdf1(this.rootKey, 0, ROOT_KEY, concatenate(previousRootKey, newK), ROOT_KEY_LENGTH_BYTES);
        kdf1(this.sendingChainKey, 0, CHAIN_KEY, concatenate(previousRootKey, newK), CHAIN_KEY_LENGTH_BYTES);
        clear(newK);
        clear(previousRootKey);
        this.i += 1;
        this.needSenderKeyRotation = false;
        return new Rotation(sharedSecret.getECDHPublicKey(), performDHRatchet ? sharedSecret.getDHPublicKey() : null,
            new byte[0]);
    }

    /**
     * Generate receiving Message Keys.
     *
     * @param ratchetId The ratchet ID as indicated in the Data message.
     * @param messageId The message ID as indicated in the Data message.
     * @return Returns corresponding MessageKeys instance.
     */
    MessageKeys generateReceivingKeys(final int ratchetId, final int messageId) {
        requireNotClosed();
        if (this.i - 1 != ratchetId || this.k != messageId) {
            throw new UnsupportedOperationException("Retrieval of previous Message Keys has not been implemented yet. Only current Message Keys can be generated.");
        }
        LOGGER.log(Level.FINEST, "Generating receiving message keys for ratchet " + ratchetId + ", message " + messageId);
        final MessageKeys keys = MessageKeys.generate(this.random, ratchetId, messageId, this.receivingChainKey);
        this.k += 1;
        kdf1(this.receivingChainKey, 0, NEXT_CHAIN_KEY, this.receivingChainKey, CHAIN_KEY_LENGTH_BYTES);
        return keys;
    }

    /**
     * Rotate the receiver key.
     *
     * For convenience, it is allowed to pass in null for each of the keys. Depending on the input, a key rotation will
     * be performed, or it will be skipped.
     *
     * @param nextECDH The other party's ECDH public key.
     * @param nextDH   The other party's DH public key.
     */
    // FIXME preserve message keys in previous ratchet before rotating away.
    void rotateReceiverKeys(@Nonnull final Point nextECDH, @Nullable final BigInteger nextDH) {
        requireNotClosed();
        LOGGER.log(Level.FINEST, "Rotating root key and receiving chain key for ratchet " + this.i);
        this.needSenderKeyRotation = true;
        this.k = 0;
        final byte[] previousRootKey = derivePreviousRootKey();
        final boolean performDHRatchet = this.i % 3 == 0;
        this.sharedSecret.rotateTheirKeys(performDHRatchet, nextECDH, nextDH);
        final byte[] newK = this.sharedSecret.getK();
        kdf1(this.rootKey, 0, ROOT_KEY, concatenate(previousRootKey, newK), ROOT_KEY_LENGTH_BYTES);
        kdf1(this.receivingChainKey, 0, CHAIN_KEY, concatenate(previousRootKey, newK), CHAIN_KEY_LENGTH_BYTES);
        clear(newK);
        clear(previousRootKey);
        this.pn = this.j;
        this.j = 0;
        this.k = 0;
        this.i += 1;
    }

    // FIXME need to clear returned root key after use
    @Nonnull
    private byte[] derivePreviousRootKey() {
        requireNotClosed();
        return this.i == 0 ? this.sharedSecret.getK() : this.rootKey.clone();
    }

    private void requireNotClosed() {
        if (this.i < 0) {
            throw new IllegalStateException("Instance was previously closed and cannot be used anymore.");
        }
    }

    /**
     * The Sender Key Rotation result.
     * <p>
     * Field `ecdhPublicKey` contains the public key of the generated ECDH key pair.
     * Field `dhPublicKey` contains the public key of the generated DH key pair.
     * Field `revealedMacs` contains all the MACs that were gathered to be revealed up to now.
     */
    static final class Rotation {
        final Point ecdhPublicKey;
        final BigInteger dhPublicKey;
        final byte[] revealedMacs;

        private Rotation(@Nonnull final Point ecdhPublicKey, @Nullable final BigInteger dhPublicKey,
                         @Nonnull final byte[] revealedMacs) {
            this.ecdhPublicKey = requireNonNull(ecdhPublicKey);
            this.dhPublicKey = dhPublicKey;
            this.revealedMacs = requireNonNull(revealedMacs);
        }
    }

    /**
     * Encryption, MAC and Extra Symmetric key keys derived from chain key.
     * <p>
     * NOTE: Please ensure that message keys are appropriately cleared by calling {@link #close()} after use.
     */
    // FIXME do not pre-calculate the MAC. It can be derived on-the-fly from the MKenc.
    // TODO consider delaying calculation of extra symmetric key (and possibly mkEnc and mkMac) to reduce the number of calculations.
    // TODO write tests that inspect private fields to discover if cleaning was successful.
    static final class MessageKeys implements AutoCloseable {

        private static final int MK_ENC_LENGTH_BYTES = 32;
        private static final int MK_MAC_LENGTH_BYTES = 64;
        private static final int EXTRA_SYMMETRIC_KEY_LENGTH_BYTES = 32;
        private static final int AUTHENTICATOR_LENGTH_BYTES = 64;

        private final SecureRandom random;

        /**
         * The ratchet ID.
         */
        private final int ratchetId;

        /**
         * The message ID.
         *
         * 'j' in case of sender message keys. 'k' in case of receiver message keys.
         */
        private final int messageId;

        /**
         * Encryption/Decryption key. (MUST be cleared after use.)
         */
        private final byte[] encrypt;

        /**
         * MAC key. (MUST be cleared after use.)
         */
        private final byte[] mac;

        /**
         * Extra Symmetric Key. (MUST be cleared after use.)
         */
        private final byte[] extraSymmetricKey;

        /**
         * Flag to indicate when MessageKeys instanced has been cleaned up.
         */
        private boolean closed = false;

        /**
         * Construct Keys instance.
         *
         * @param random            The random generator instance.
         * @param ratchetId         The ratchet ID on which this Message Keys set is based.
         * @param messageId         The message ID on which this Message Keys set is based.
         * @param encrypt           message key for encryption
         * @param mac               message key for message authentication
         * @param extraSymmetricKey extra symmetric key
         */
        private MessageKeys(@Nonnull final SecureRandom random, final int ratchetId, final int messageId,
                            @Nonnull final byte[] encrypt, @Nonnull final byte[] mac,
                            @Nonnull final byte[] extraSymmetricKey) {
            this.random = requireNonNull(random);
            this.ratchetId = ratchetId;
            this.messageId = messageId;
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
        private static MessageKeys generate(@Nonnull final SecureRandom random, final int ratchetId,
                                            final int messageId, @Nonnull final byte[] chainKey) {
            final byte[] encrypt = new byte[MK_ENC_LENGTH_BYTES];
            kdf1(encrypt, 0, MESSAGE_KEY, chainKey, MK_ENC_LENGTH_BYTES);
            final byte[] mac = new byte[MK_MAC_LENGTH_BYTES];
            // TODO consider delaying calculation of MAC key to when needed. (Is derived from MKenc.)
            kdf1(mac, 0, MAC_KEY, encrypt, MK_MAC_LENGTH_BYTES);
            final byte[] extraSymmetricKey = new byte[EXTRA_SYMMETRIC_KEY_LENGTH_BYTES];
            kdf1(extraSymmetricKey, 0, EXTRA_SYMMETRIC_KEY, chainKey, EXTRA_SYMMETRIC_KEY_LENGTH_BYTES);
            return new MessageKeys(random, ratchetId, messageId, encrypt, mac, extraSymmetricKey);
        }

        /**
         * Clear sensitive material.
         */
        @Override
        public void close() {
            clear(this.encrypt);
            clear(this.mac);
            clear(this.extraSymmetricKey);
            this.closed = true;
        }

        /**
         * Return the ratchet ID for this set of Message keys.
         *
         * @return Returns the ratchet ID.
         */
        int getRatchetId() {
            return ratchetId;
        }

        /**
         * Return the message ID for this set of Message keys.
         *
         * @return Returns the message ID.
         */
        int getMessageId() {
            return messageId;
        }

        /**
         * Encrypt a message using a random nonce.
         *
         * @param message The plaintext message.
         * @return Returns a result containing the ciphertext and nonce used.
         */
        @Nonnull
        Result encrypt(@Nonnull final byte[] message) {
            requireNotClosed();
            final byte[] nonce = generateNonce(random);
            final byte[] ciphertext = OtrCryptoEngine4.encrypt(this.encrypt, nonce, message);
            return new Result(nonce, ciphertext);
        }

        /**
         * Decrypt a ciphertext.
         *
         * @param ciphertext The ciphertext.
         * @param nonce      The nonce corresponding to the ciphertext.
         * @return Returns the plaintext message.
         */
        @Nonnull
        byte[] decrypt(@Nonnull final byte[] ciphertext, @Nonnull final byte[] nonce) {
            requireNotClosed();
            return OtrCryptoEngine4.decrypt(this.encrypt, nonce, ciphertext);
        }

        /**
         * Get the authenticator (MAC).
         * <p>
         * This method only performs the final hash calculation that includes the MAC key. The internal hash calculation
         * defined by OTRv4 is expected to be performed prior to calling this method:
         * <pre>
         *     KDF_1(usageDataMessageSections || data_message_sections, 64)
         * </pre>
         *
         * @param dataMessageSectionsHash The hash calculation over the data message sections (excluding Authenticator
         *                                and Revealed MACs).
         * @return Returns the MAC. (Must be cleared separately.)
         */
        @Nonnull
        byte[] authenticate(@Nonnull final byte[] dataMessageSectionsHash) {
            requireNotClosed();
            return kdf1(AUTHENTICATOR, concatenate(this.mac, dataMessageSectionsHash), AUTHENTICATOR_LENGTH_BYTES);
        }

        /**
         * Verify a given authenticator against the expected authentication hash.
         *
         * @param dataMessageSectionHash The data message section hash to be authenticated.
         * @param authenticator          The authenticator value.
         */
        void verify(@Nonnull final byte[] dataMessageSectionHash, @Nonnull final byte[] authenticator)
            throws VerificationException {
            requireNotClosed();
            final byte[] expectedAuthenticator = authenticate(dataMessageSectionHash);
            if (!constantTimeEquals(expectedAuthenticator, authenticator)) {
                throw new VerificationException("The authenticator is invalid.");
            }
            // FIXME add MAC key to Revealed MACs after use.
        }

        /**
         * Get the Extra Symmetric Key.
         *
         * @return Returns the Extra Symmetric Key. (Instance must be cleared by user.)
         */
        @Nonnull
        byte[] getExtraSymmetricKey() {
            requireNotClosed();
            return extraSymmetricKey.clone();
        }

        private void requireNotClosed() {
            if (this.closed) {
                throw new IllegalStateException("BUG: Use of closed MessageKeys instance.");
            }
        }

        /**
         * The result class representation the result of an encryption activity.
         * <p>
         * The instance contains the ciphertext as well as the nonce used during encryption.
         */
        static final class Result {
            final byte[] nonce;
            final byte[] ciphertext;

            private Result(@Nonnull final byte[] nonce, @Nonnull final byte[] ciphertext) {
                this.nonce = requireNonNull(nonce);
                this.ciphertext = requireNonNull(ciphertext);
            }
        }

        /**
         * The VerificationException indicates a failure to verify the authenticator.
         */
        static final class VerificationException extends Exception {

            private VerificationException(@Nonnull final String message) {
                super(message);
            }
        }
    }
}
