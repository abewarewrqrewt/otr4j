package net.java.otr4j.session.state;

import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
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
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.DATA_MESSAGE_SECTIONS;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.EXTRA_SYMMETRIC_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.MAC_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.MESSAGE_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.NEXT_CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateNonce;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
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
final class DoubleRatchet implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DoubleRatchet.class.getName());

    private static final int DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES = 64;

    private static final int ROOT_KEY_LENGTH_BYTES = 64;

    private final SecureRandom random;

    private final SharedSecret4 sharedSecret;

    private final ByteArrayOutputStream macsToReveal = new ByteArrayOutputStream();

    /**
     * The 'root key' in the Double Ratchet. The root key is shared between sender and receiver ratchets.
     */
    private final byte[] rootKey;

    /**
     * Sender ratchet represents the ratchet process on the part of the message sender.
     * <p>
     * The sender ratchet contains message ID 'j'.
     */
    private final Ratchet senderRatchet;

    /**
     * Receiver ratchet represents the ratchet process on part of the message receiver.
     * <p>
     * The receiver ratchet contains message ID 'k'.
     */
    private final Ratchet receiverRatchet;

    /**
     * The next ratchet ID.
     * <p>
     * NOTE: 'i' is incremented as soon as a rotation has finished. For typical use outside of this class, one would use
     * need value 'i - 1', instead of 'i'.
     */
    private int i = 0;

    /**
     * The number of messages in the previous ratchet, i.e. sender ratchet message number.
     */
    private int pn = 0;

    DoubleRatchet(@Nonnull final SecureRandom random, @Nonnull final SharedSecret4 sharedSecret,
            @Nonnull final byte[] initialRootKey) {
        this.random = requireNonNull(random);
        this.sharedSecret = requireNonNull(sharedSecret);
        this.rootKey = requireLengthExactly(ROOT_KEY_LENGTH_BYTES, initialRootKey);
        assert !allZeroBytes(this.rootKey) : "Expected random data, instead of all zero-bytes. There might be something severely wrong.";
        this.senderRatchet = new Ratchet();
        this.receiverRatchet = new Ratchet();
    }

    @Override
    public void close() {
        clear(this.rootKey);
        this.i = MIN_VALUE;
        this.pn = 0;
        this.sharedSecret.close();
        if (this.macsToReveal.size() > 0) {
            throw new IllegalStateException("BUG: Remaining MACs have not been revealed. Failure to accomplish full deniability.");
        }
        this.macsToReveal.reset();
        this.senderRatchet.close();
        this.receiverRatchet.close();
    }

    /**
     * Indicates whether or not Sender key rotation is required before encrypting/authenticating the next message to be
     * sent.
     *
     * @return Returns true iff sender key rotation is required.
     */
    @CheckReturnValue
    boolean isNeedSenderKeyRotation() {
        return senderRatchet.needsRotation;
    }

    /**
     * The ratchet ID ('i')
     *
     * @return Returns current ratchet ID.
     */
    int getI() {
        return this.i - 1;
    }

    /**
     * The sender message ID ('j')
     *
     * @return Returns message ID.
     */
    int getJ() {
        return this.senderRatchet.messageID;
    }

    /**
     * The receiver message ID ('k')
     *
     * @return Returns message ID.
     */
    int getK() {
        return this.receiverRatchet.messageID;
    }

    /**
     * Number of (sender) messages in previous ratchet.
     *
     * @return Returns number of messages.
     */
    int getPn() {
        return pn;
    }

    @Nonnull
    Point getECDHPublicKey() {
        return this.sharedSecret.getECDHPublicKey();
    }

    @Nonnull
    RotationResult rotateSenderKeys() {
        requireNotClosed();
        if (!this.senderRatchet.needsRotation) {
            throw new IllegalStateException("Rotation is only allowed after new public key material was received from the other party.");
        }
        if (this.sharedSecret.getTheirECDHPublicKey() == null || this.sharedSecret.getTheirDHPublicKey() == null) {
            throw new IllegalStateException("Cannot perform sender key rotation until other party's public keys have been received.");
        }
        // Perform sender key rotation.
        LOGGER.log(Level.FINEST, "Rotating root key and sending chain key for ratchet " + this.i);
        final boolean performDHRatchet = this.i % 3 == 0;
        final byte[] previousRootKey = this.rootKey.clone();
        this.sharedSecret.rotateOurKeys(performDHRatchet);
        final byte[] newK = this.sharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(previousRootKey, newK);
        kdf1(this.rootKey, 0, ROOT_KEY, concatPreviousRootKeyNewK, ROOT_KEY_LENGTH_BYTES);
        this.senderRatchet.rotateKeys(concatPreviousRootKeyNewK);
        clear(concatPreviousRootKeyNewK);
        clear(newK);
        clear(previousRootKey);
        this.i += 1;
        // Extract MACs to reveal.
        final byte[] revealedMacs = this.macsToReveal.toByteArray();
        this.macsToReveal.reset();
        return new RotationResult(performDHRatchet ? this.sharedSecret.getDHPublicKey() : null, revealedMacs);
    }

    /**
     * Encrypt provided data with the current sending message keys. In the process, generate a nonce required for
     * encryption.
     *
     * @param data the data
     * @return Returns a composite result consisting of the generated nonce and the ciphertext.
     */
    @Nonnull
    EncryptionResult encrypt(@Nonnull final byte[] data) {
        LOGGER.log(Level.FINEST, "Generating message keys for encryption of ratchet {0}, message {1}.",
                new Object[]{this.i - 1, this.senderRatchet.messageID});
        try (MessageKeys keys = this.generateSendingKeys()) {
            return keys.encrypt(data);
        }
    }

    /**
     * Generate an authenticator value for later content verification.
     *
     * @param dataMessageSectionsContent the hash of the data message sections
     * @return Returns authenticator value.
     */
    @Nonnull
    byte[] authenticate(@Nonnull final byte[] dataMessageSectionsContent) {
        LOGGER.log(Level.FINEST, "Generating message keys for authentication of ratchet {0}, message {1}.",
                new Object[]{this.i - 1, this.senderRatchet.messageID});
        final byte[] messageMAC = kdf1(DATA_MESSAGE_SECTIONS, dataMessageSectionsContent,
            DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES);
        try (MessageKeys keys = this.generateSendingKeys()) {
            return keys.authenticate(messageMAC);
        } finally {
            clear(messageMAC);
        }
    }

    @Nonnull
    private MessageKeys generateSendingKeys() {
        final byte[] chainKey = this.senderRatchet.getChainKey();
        final MessageKeys keys = generateMessageKeys(chainKey);
        clear(chainKey);
        return keys;
    }

    /**
     * Decrypt message contents.
     *
     * @param ratchetId  the ratchet ID of the current message
     * @param messageId  the message ID of the current message
     * @param ciphertext the (encrypted) ciphertext
     * @param nonce      the nonce that was used during the encryption process
     * @return Returns decrypted message contents.
     */
    @Nonnull
    byte[] decrypt(final int ratchetId, final int messageId, @Nonnull final byte[] ciphertext, @Nonnull final byte[] nonce)
            throws RotationLimitationException {
        LOGGER.log(Level.FINEST, "Generating message keys for decryption of ratchet {0}, message {1}.",
                new Object[] {this.i - 1, this.receiverRatchet.messageID});
        try (MessageKeys keys = generateReceivingKeys(ratchetId, messageId)) {
            return keys.decrypt(ciphertext, nonce);
        }
    }

    /**
     * Verify message contents using an authenticator.
     *
     * @param ratchetId                  the ratchet ID
     * @param messageId                  the message ID
     * @param dataMessageSectionsContent the hash of the data message sections
     * @param authenticator              the authenticator
     * @throws RotationLimitationException Failure to perform key rotation towards the necessary message keys.
     * @throws VerificationException Thrown in case verification has failed.
     */
    void verify(final int ratchetId, final int messageId, @Nonnull final byte[] dataMessageSectionsContent,
            @Nonnull final byte[] authenticator) throws RotationLimitationException, VerificationException {
        LOGGER.log(Level.FINEST, "Generating message keys for verification of ratchet {0}, message {1}.",
                new Object[]{this.i - 1, this.receiverRatchet.messageID});
        try (MessageKeys keys = generateReceivingKeys(ratchetId, messageId)) {
            final byte[] digest = kdf1(DATA_MESSAGE_SECTIONS, dataMessageSectionsContent,
                DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES);
            keys.verify(digest, authenticator);
            this.macsToReveal.write(authenticator, 0, authenticator.length);
            clear(digest);
        }
    }

    /**
     * Generate receiving Message Keys.
     *
     * @param ratchetId The ratchet ID as indicated in the Data message.
     * @param messageId The message ID as indicated in the Data message.
     * @return Returns corresponding MessageKeys instance.
     * @throws RotationLimitationException Indicates that we cross a ratchet boundary and therefore we cannot fast-forward
     *                               rotations to a point where the right message keys can be generated. This is a
     *                               limitation of the Double Ratchet. Matching message keys cannot be generated.
     */
    // TODO preserve message keys before rotating past ratchetId, messageId combination.
    private MessageKeys generateReceivingKeys(final int ratchetId, final int messageId) throws RotationLimitationException {
        requireNotClosed();
        if (this.i - 1 > ratchetId || this.receiverRatchet.messageID > messageId) {
            throw new UnsupportedOperationException("Retrieval of previous Message Keys has not been implemented yet. Only current Message Keys can be generated.");
        } else if (this.i - 1 < ratchetId) {
            // The first message in the new ratchet provides us with the information we need to generate missing message
            // keys in previous ratchet, as well as necessary key material to decrypt and authenticate the message.
            // There is no way to process this message given that this information is missing.
            throw new RotationLimitationException("Cannot fast-forward-rotate receiving keys over first message in new ratchet. We have not encountered the first message in the new ratchet.");
        }
        // TODO verify that number of messages needing to fast-forward is acceptable. (max_skip in OTRv4 spec)
        while (this.receiverRatchet.messageID < messageId) {
            LOGGER.log(Level.FINEST, "Fast-forward rotating receiving chain key to catch up with message ID: " + messageId);
            this.receiverRatchet.rotateChainKey();
            // TODO store intermediate message keys for previous messages as the message may arrive out-of-order
        }
        final byte[] chainKey = this.receiverRatchet.getChainKey();
        final MessageKeys keys = generateMessageKeys(chainKey);
        clear(chainKey);
        return keys;
    }

    /**
     * Rotate the sending chain key.
     */
    void rotateSendingChainKey() {
        this.senderRatchet.rotateChainKey();
    }

    /**
     * Rotate the receiving chain key.
     */
    void rotateReceivingChainKey() {
        this.receiverRatchet.rotateChainKey();
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
    void rotateReceiverKeys(@Nonnull final Point nextECDH, @Nullable final BigInteger nextDH) throws OtrCryptoException {
        requireNotClosed();
        LOGGER.log(Level.FINEST, "Rotating root key and receiving chain key for ratchet {0} (nextDH = {1})",
                new Object[]{this.i, nextDH != null});
        final boolean performDHRatchet = this.i % 3 == 0;
        final byte[] previousRootKey = this.rootKey.clone();
        this.sharedSecret.rotateTheirKeys(performDHRatchet, nextECDH, nextDH);
        this.pn = this.senderRatchet.messageID;
        final byte[] newK = this.sharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(previousRootKey, newK);
        kdf1(this.rootKey, 0, ROOT_KEY, concatPreviousRootKeyNewK, ROOT_KEY_LENGTH_BYTES);
        this.receiverRatchet.rotateKeys(concatPreviousRootKeyNewK);
        clear(concatPreviousRootKeyNewK);
        clear(newK);
        clear(previousRootKey);
        this.senderRatchet.needsRotation = true;
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
        assert !allZeroBytes(chainkey) : "Expected chainkey of random data instead of all zero-bytes.";
        final byte[] encrypt = kdf1(MESSAGE_KEY, chainkey, MessageKeys.MK_ENC_LENGTH_BYTES);
        final byte[] extraSymmetricKey = kdf1(EXTRA_SYMMETRIC_KEY, chainkey, MessageKeys.EXTRA_SYMMETRIC_KEY_LENGTH_BYTES);
        return new MessageKeys(this.random, encrypt, extraSymmetricKey);
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
    static final class RotationResult {

        final BigInteger dhPublicKey;
        final byte[] revealedMacs;

        private RotationResult(@Nullable final BigInteger dhPublicKey, @Nonnull final byte[] revealedMacs) {
            this.dhPublicKey = dhPublicKey;
            this.revealedMacs = requireNonNull(revealedMacs);
        }
    }

    /**
     * Ratchet, the individual ratchet used for either sending or receiving.
     */
    private final static class Ratchet implements AutoCloseable {

        private static final int CHAIN_KEY_LENGTH_BYTES = 64;

        /**
         * The chain key.
         * <p>
         * The key relies on a first key rotation to become initialized.
         */
        private final byte[] chainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

        /**
         * Message ID.
         */
        private int messageID = 0;

        /**
         * The boolean indicates that we need key rotation before we have sensible data to work with. (Initially, the
         * chain key is all-zero.)
         */
        private boolean needsRotation = true;

        @Override
        public void close() {
            this.messageID = MIN_VALUE;
            clear(this.chainKey);
        }

        /**
         * Acquire ratchet's chain key.
         * <p>
         * NOTE: caller needs to clear the return key after use.
         *
         * @return Returns chain key.
         */
        byte[] getChainKey() {
            requireNotClosed();
            requireRotationNotNeeded();
            return this.chainKey.clone();
        }

        /**
         * Rotate the chain key.
         * <p>
         * Generate a new chain key based on the old chain key and increment the message ID.
         */
        void rotateChainKey() {
            requireNotClosed();
            requireRotationNotNeeded();
            this.messageID += 1;
            kdf1(this.chainKey, 0, NEXT_CHAIN_KEY, this.chainKey, CHAIN_KEY_LENGTH_BYTES);
        }

        /**
         * Rotate the ratchet key.
         */
        void rotateKeys(@Nonnull final byte[] concatPreviousRootKeyNewK) {
            requireNotClosed();
            this.messageID = 0;
            kdf1(this.chainKey, 0, CHAIN_KEY, concatPreviousRootKeyNewK, CHAIN_KEY_LENGTH_BYTES);
            this.needsRotation = false;
        }

        private void requireRotationNotNeeded() {
            if (this.needsRotation) {
                throw new IllegalStateException("Key rotation needs to be performed before new keys can be generated.");
            }
        }

        private void requireNotClosed() {
            if (this.messageID < 0) {
                throw new IllegalStateException("Ratchet instance is already closed.");
            }
        }
    }

    /**
     * Encrypt/decrypt and authenticate/verify using the secret key material in the MessageKeys.
     * <p>
     * NOTE: Please ensure that message keys are appropriately cleared by calling {@link #close()} after use.
     */
    // TODO write tests that inspect private fields to discover if cleaning was successful.
    private static final class MessageKeys implements AutoCloseable {

        private static final int MK_ENC_LENGTH_BYTES = 32;
        private static final int MK_MAC_LENGTH_BYTES = 64;
        private static final int EXTRA_SYMMETRIC_KEY_LENGTH_BYTES = 32;
        private static final int AUTHENTICATOR_LENGTH_BYTES = 64;

        private final SecureRandom random;

        /**
         * Flag to indicate when MessageKeys instanced has been cleaned up.
         */
        private boolean closed = false;

        /**
         * Encryption/Decryption key. (MUST be cleared after use.)
         */
        private final byte[] encrypt;

        /**
         * Extra Symmetric Key. (MUST be cleared after use.)
         */
        private final byte[] extraSymmetricKey;

        /**
         * Construct Keys instance.
         *
         * @param random            SecureRandom instance
         * @param encrypt           message key for encryption
         * @param extraSymmetricKey extra symmetric key
         */
        private MessageKeys(@Nonnull final SecureRandom random, @Nonnull final byte[] encrypt,
                @Nonnull final byte[] extraSymmetricKey) {
            this.random = requireNonNull(random);
            assert !allZeroBytes(encrypt) : "Expected encryption key of \"random\" data, instead of all zero-bytes.";
            this.encrypt = requireLengthExactly(MK_ENC_LENGTH_BYTES, encrypt);
            assert !allZeroBytes(extraSymmetricKey) : "Expected extra symmetric key of \"random\" data, instead of all zero-bytes.";
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
         * Encrypt a message using a random nonce.
         *
         * @param message The plaintext message.
         * @return Returns a result containing the ciphertext and nonce used.
         */
        @Nonnull
        EncryptionResult encrypt(@Nonnull final byte[] message) {
            requireNotClosed();
            final byte[] nonce = generateNonce(random);
            final byte[] ciphertext = OtrCryptoEngine4.encrypt(this.encrypt, nonce, message);
            return new EncryptionResult(nonce, ciphertext);
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
            final byte[] mac = generateMAC();
            final byte[] concatMacDataMessageSectionsHash = concatenate(mac, dataMessageSectionsHash);
            final byte[] authenticator = kdf1(AUTHENTICATOR, concatMacDataMessageSectionsHash, AUTHENTICATOR_LENGTH_BYTES);
            clear(concatMacDataMessageSectionsHash);
            clear(mac);
            return authenticator;
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
            } finally {
                clear(expectedAuthenticator);
            }
        }

        @Nonnull
        private byte[] generateMAC() {
            requireNotClosed();
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
    static final class EncryptionResult {

        final byte[] nonce;
        final byte[] ciphertext;

        private EncryptionResult(@Nonnull final byte[] nonce, @Nonnull final byte[] ciphertext) {
            this.nonce = requireNonNull(nonce);
            this.ciphertext = requireNonNull(ciphertext);
        }
    }

    /**
     * This is used to indicate that a boundary is reached that the DoubleRatchet cannot handle.
     */
    static final class RotationLimitationException extends Exception {

        private static final long serialVersionUID = -2200918867384812098L;

        private RotationLimitationException(@Nonnull final String message) {
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
