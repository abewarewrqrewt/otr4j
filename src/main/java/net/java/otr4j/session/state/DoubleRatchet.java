package net.java.otr4j.session.state;

import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.SharedSecret4;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.Integer.MIN_VALUE;
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

/**
 * The Double Ratchet. (OTRv4)
 * <p>
 * The mechanism according to which the key rotations are performed. The rotation happen in lock-step between the two
 * parties. The Double Ratchet recognizes 3 types of keys: root key, chain key (sending, receiving) and message keys.
 * <p>
 * Key rotations consist of 2 cases:
 * <ol>
 * <li>Every third ratchet, starting at the first ratchet: rotate the DH key and derive key material from the new DH key
 * pair.</li>
 * <li>Other two ratchets: rotate key material based on symmetric key (brace key) only.</li>
 * </ol>
 * <p>
 * DoubleRatchet is NOT thread-safe.
 */
// TODO DoubleRatchet currently does not keep history. Therefore it is not possible to decode out-of-order messages from previous ratchets. (Also needed to keep MessageKeys instances for messages failing verification.)
// TODO consider adding a counter/semaphore in order to verify that "at most one" (depending on circumstances) set of message keys is active at a time. Ensures that message keys are appropriately cleaned after use.
// FIXME closing ratchet should also close any remaining message keys
// FIXME finish writing unit tests after ratchet implementation is finished.
// TODO is it possible to use the same Chain Key for more than 1 message?
// FIXME add support for disclosure of MACs at session ending or session expiration.
final class DoubleRatchet implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DoubleRatchet.class.getName());

    private static final int ROOT_KEY_LENGTH_BYTES = 64;
    private static final int CHAIN_KEY_LENGTH_BYTES = 64;

    private final SecureRandom random;

    private final SharedSecret4 sharedSecret;

    private final ByteArrayOutputStream macsToReveal = new ByteArrayOutputStream();

    private final byte[] rootKey;

    /**
     * The sending chain key.
     * <p>
     * The key relies on a first key rotation to become initialized.
     */
    private final byte[] sendingChainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

    /**
     * The receiving chain key.
     * <p>
     * The key relies on a first key rotation to become initialized.
     */
    private final byte[] receivingChainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

    /**
     * The boolean indicates that we need sender key rotation before we have sensible data to work with. (Initially, the
     * sending chain key is all-zero.)
     */
    private boolean needSenderKeyRotation = true;

    /**
     * The boolean indicates that we need receiver key rotation before we have sensible data to work with. (Initially,
     * the receiver chain key is all-zero.)
     */
    private boolean needReceiverKeyRotation = true;

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

    DoubleRatchet(@Nonnull final SecureRandom random, @Nonnull final SharedSecret4 sharedSecret,
                  @Nonnull final byte[] initialRootKey) {
        this.random = requireNonNull(random);
        this.sharedSecret = requireNonNull(sharedSecret);
        this.rootKey = requireLengthExactly(ROOT_KEY_LENGTH_BYTES, initialRootKey);
    }

    @Override
    public void close() {
        clear(this.rootKey);
        clear(this.receivingChainKey);
        clear(this.sendingChainKey);
        this.i = MIN_VALUE;
        this.j = 0;
        this.k = 0;
        this.pn = 0;
        this.sharedSecret.close();
        if (this.macsToReveal.size() > 0) {
            throw new IllegalStateException("BUG: Remaining MACs have not been revealed. Failure to accomplish full deniability.");
        }
        this.macsToReveal.reset();
    }

    @CheckReturnValue
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
    MessageKeys generateSendingKeys() {
        requireNotClosed();
        if (this.needSenderKeyRotation) {
            throw new IllegalStateException("Key rotation needs to be performed before new sending keys can be generated.");
        }
        LOGGER.log(Level.FINEST, "Generating sending message keys for ratchet " + (this.i - 1) + ", message " + this.j);
        final MessageKeys keys = generateMessageKeys(this.sendingChainKey);
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
        if (this.sharedSecret.getTheirECDHPublicKey() == null || this.sharedSecret.getTheirDHPublicKey() == null) {
            throw new IllegalStateException("Cannot perform sender key rotation until other party's public keys have been received.");
        }
        // Perform sender key rotation.
        LOGGER.log(Level.FINEST, "Rotating root key and sending chain key for ratchet " + this.i);
        this.j = 0;
        final byte[] previousRootKey = this.rootKey.clone();
        final boolean performDHRatchet = this.i % 3 == 0;
        this.sharedSecret.rotateOurKeys(performDHRatchet);
        final byte[] newK = this.sharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(previousRootKey, newK);
        kdf1(this.rootKey, 0, ROOT_KEY, concatPreviousRootKeyNewK, ROOT_KEY_LENGTH_BYTES);
        kdf1(this.sendingChainKey, 0, CHAIN_KEY, concatPreviousRootKeyNewK, CHAIN_KEY_LENGTH_BYTES);
        clear(newK);
        clear(previousRootKey);
        clear(concatPreviousRootKeyNewK);
        this.i += 1;
        this.needSenderKeyRotation = false;
        // Extract MACs to reveal.
        final byte[] revealedMacs = this.macsToReveal.toByteArray();
        this.macsToReveal.reset();
        return new Rotation(performDHRatchet ? this.sharedSecret.getDHPublicKey() : null, revealedMacs);
    }

    /**
     * Generate receiving Message Keys.
     *
     * @param ratchetId The ratchet ID as indicated in the Data message.
     * @param messageId The message ID as indicated in the Data message.
     * @return Returns corresponding MessageKeys instance.
     * @throws KeyRotationLimitation Indicates that we cross a ratchet boundary and therefore we cannot fast-forward
     *                               rotations to a point where the right message keys can be generated. This is a
     *                               limitation of the Double Ratchet. Matching message keys cannot be generated.
     */
    // TODO preserve message keys before rotating past ratchetId, messageId combination.
    MessageKeys generateReceivingKeys(final int ratchetId, final int messageId) throws KeyRotationLimitation {
        requireNotClosed();
        requireReceiverKeyRotation();
        if (this.i - 1 > ratchetId || this.k > messageId) {
            throw new UnsupportedOperationException("Retrieval of previous Message Keys has not been implemented yet. Only current Message Keys can be generated.");
        } else if (this.i - 1 < ratchetId) {
            // The first message in the new ratchet provides us with the information we need to generate missing message
            // keys in previous ratchet, as well as necessary key material to decrypt and authenticate the message.
            // There is no way to process this message given that this information is missing.
            throw new KeyRotationLimitation("Cannot fast-forward-rotate receiving keys over first message in new ratchet. We have not encountered the first message in the new ratchet.");
        }
        // TODO verify that number of messages needing to fast-forward is acceptable. (max_skip in OTRv4 spec)
        while (this.k < messageId) {
            LOGGER.log(Level.FINEST, "Fast-forward rotating receiving chain key to catch up with message ID: " + messageId);
            rotateReceivingChainKey();
            // TODO store intermediate message keys for previous messages as the message may arrive out-of-order
        }
        LOGGER.log(Level.FINEST, "Generating receiving message keys for ratchet {0}, message {1}.",
            new Object[]{ratchetId, messageId});
        return generateMessageKeys(this.receivingChainKey);
    }

    /**
     * Rotate the receiving chain key.
     * <p>
     * Generate a new chain key based on the old chain key and increment the receiver counter 'k'.
     */
    void rotateReceivingChainKey() {
        requireNotClosed();
        requireReceiverKeyRotation();
        this.k += 1;
        kdf1(this.receivingChainKey, 0, NEXT_CHAIN_KEY, this.receivingChainKey, CHAIN_KEY_LENGTH_BYTES);
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
    // TODO preserve message keys in previous ratchet before rotating away.
    void rotateReceiverKeys(@Nonnull final Point nextECDH, @Nullable final BigInteger nextDH) {
        requireNotClosed();
        LOGGER.log(Level.FINEST, "Rotating root key and receiving chain key for ratchet {0} (nextDH = {1})",
            new Object[]{this.i, nextDH != null});
        this.needReceiverKeyRotation = false;
        this.needSenderKeyRotation = true;
        this.k = 0;
        final byte[] previousRootKey = this.rootKey.clone();
        final boolean performDHRatchet = this.i % 3 == 0;
        this.sharedSecret.rotateTheirKeys(performDHRatchet, nextECDH, nextDH);
        final byte[] newK = this.sharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(previousRootKey, newK);
        kdf1(this.rootKey, 0, ROOT_KEY, concatPreviousRootKeyNewK, ROOT_KEY_LENGTH_BYTES);
        kdf1(this.receivingChainKey, 0, CHAIN_KEY, concatPreviousRootKeyNewK, CHAIN_KEY_LENGTH_BYTES);
        clear(newK);
        clear(previousRootKey);
        clear(concatPreviousRootKeyNewK);
        this.pn = this.j;
        this.j = 0;
        this.k = 0;
        this.i += 1;
    }

    /**
     * Get the remaining MAC keys to be revealed. (And remove them from the internal list to be revealed.)
     * <p>
     * NOTE: this method should only used to acquire the last remaining MAC keys prior to a session end. The general
     * revelation case is facilitated through key rotation, i.e. {@link #rotateSenderKeys()}.
     *
     * @return Returns the remaining MAC keys to reveal.
     */
    byte[] collectRemainingMACsToReveal() {
        requireNotClosed();
        final byte[] revealed = this.macsToReveal.toByteArray();
        this.macsToReveal.reset();
        return revealed;
    }

    private MessageKeys generateMessageKeys(@Nonnull final byte[] chainkey) {
        final byte[] encrypt = kdf1(MESSAGE_KEY, chainkey, MessageKeys.MK_ENC_LENGTH_BYTES);
        final byte[] extraSymmetricKey = kdf1(EXTRA_SYMMETRIC_KEY, chainkey, MessageKeys.EXTRA_SYMMETRIC_KEY_LENGTH_BYTES);
        return new MessageKeys(this.i-1, this.j, encrypt, extraSymmetricKey);
    }

    private void requireNotClosed() {
        if (this.i < 0) {
            throw new IllegalStateException("Instance was previously closed and cannot be used anymore.");
        }
    }

    private void requireReceiverKeyRotation() {
        if (this.needReceiverKeyRotation) {
            throw new IllegalStateException("Receiver key rotation needs to be performed.");
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
        final BigInteger dhPublicKey;
        final byte[] revealedMacs;

        private Rotation(@Nullable final BigInteger dhPublicKey, @Nonnull final byte[] revealedMacs) {
            this.dhPublicKey = dhPublicKey;
            this.revealedMacs = requireNonNull(revealedMacs);
        }
    }

    /**
     * Encrypt/decrypt and authenticate/verify using the secret key material in the MessageKeys.
     * <p>
     * NOTE: Please ensure that message keys are appropriately cleared by calling {@link #close()} after use.
     */
    // TODO write tests that inspect private fields to discover if cleaning was successful.
    final class MessageKeys implements AutoCloseable {

        private static final int MK_ENC_LENGTH_BYTES = 32;
        private static final int MK_MAC_LENGTH_BYTES = 64;
        private static final int EXTRA_SYMMETRIC_KEY_LENGTH_BYTES = 32;
        private static final int AUTHENTICATOR_LENGTH_BYTES = 64;

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
         * @param ratchetId         The ratchet ID on which this Message Keys set is based.
         * @param messageId         The message ID on which this Message Keys set is based.
         * @param encrypt           message key for encryption
         * @param extraSymmetricKey extra symmetric key
         */
        private MessageKeys(final int ratchetId, final int messageId, @Nonnull final byte[] encrypt,
                            @Nonnull final byte[] extraSymmetricKey) {
            this.ratchetId = ratchetId;
            this.messageId = messageId;
            this.encrypt = requireLengthExactly(MK_ENC_LENGTH_BYTES, encrypt);
            this.extraSymmetricKey = requireLengthExactly(EXTRA_SYMMETRIC_KEY_LENGTH_BYTES, extraSymmetricKey);
        }

        /**
         * Clear sensitive material.
         */
        @Override
        public void close() {
            clear(this.encrypt);
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
            final byte[] mac = generateMAC();
            final byte[] concatMacDataMessageSectionsHash = concatenate(mac, dataMessageSectionsHash);
            try {
                return kdf1(AUTHENTICATOR, concatMacDataMessageSectionsHash, AUTHENTICATOR_LENGTH_BYTES);
            } finally {
                clear(concatMacDataMessageSectionsHash);
                clear(mac);
            }
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
            try {
                if (!constantTimeEquals(expectedAuthenticator, authenticator)) {
                    throw new VerificationException("The authenticator is invalid.");
                }
                DoubleRatchet.this.macsToReveal.write(authenticator, 0, authenticator.length);
            } finally {
                clear(expectedAuthenticator);
            }
        }

        @Nonnull
        private byte[] generateMAC() {
            return kdf1(MAC_KEY, this.encrypt, MK_MAC_LENGTH_BYTES);
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

    static final class KeyRotationLimitation extends Exception {

        private static final long serialVersionUID = -2200918867384812098L;

        private KeyRotationLimitation(@Nonnull final String message) {
            super(message);
        }
    }

    /**
     * The VerificationException indicates a failure to verify the authenticator.
     */
    static final class VerificationException extends Exception {

        private static final long serialVersionUID = 2169901253478095348L;

        private VerificationException(@Nonnull final String message) {
            super(message);
        }
    }
}
