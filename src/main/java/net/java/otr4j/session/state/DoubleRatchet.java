/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Logger;

import static java.lang.Integer.MIN_VALUE;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
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
 * The logistics of the Double Ratchet-algorithm. The mechanism according to which the key rotations are performed. The
 * cryptographic secrets updates are performed in {@link SharedSecret4}.
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
// FIXME adopt second-redesigned Double Ratchet algorithm (removed `i` - ratchet ID)
final class DoubleRatchet implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DoubleRatchet.class.getName());

    private static final int DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES = 64;

    private static final int ROOT_KEY_LENGTH_BYTES = 64;

    private final ByteArrayOutputStream macsToReveal = new ByteArrayOutputStream();

    /**
     * Sender ratchet represents the ratchet process on the part of the message sender.
     * <p>
     * The sender ratchet contains message ID 'j'.
     */
    private final Ratchet senderRatchet = new Ratchet();

    /**
     * Receiver ratchet represents the ratchet process on part of the message receiver.
     * <p>
     * The receiver ratchet contains message ID 'k'.
     */
    private final Ratchet receiverRatchet = new Ratchet();

    private final SecureRandom random;

    private final SharedSecret4 sharedSecret;

    /**
     * The 'root key' in the Double Ratchet. The root key is shared between sender and receiver ratchets.
     */
    private final byte[] rootKey;

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
            @Nonnull final byte[] initialRootKey, @Nonnull final Role role) {
        requireNonNull(role);
        this.random = requireNonNull(random);
        this.sharedSecret = requireNonNull(sharedSecret);
        this.rootKey = requireLengthExactly(ROOT_KEY_LENGTH_BYTES, initialRootKey);
        assert !allZeroBytes(this.rootKey) : "Expected random data, instead of all zero-bytes. There might be something severely wrong.";
        switch (role) {
        case BOB:
            generateRatchetKeys(Purpose.RECEIVING);
            this.senderRatchet.needsRotation = true;
            // As we set the `needsRotation` flag on the sender ratchet, next time a message is sent new ratchet keys
            // will be generated. According to the Double Ratchet initialization in OTRv4 spec, we should do this
            // immediately. However, the steps are exactly the same and generating them here means we need to find a way
            // to put the public keys into the next data message. This makes things a lot more complicated and in the
            // end achieves the exact same effect.
            break;
        case ALICE:
            generateRatchetKeys(Purpose.SENDING);
            this.senderRatchet.needsRotation = false;
            break;
        default:
            throw new UnsupportedOperationException("Unsupported purpose.");
        }
    }

    @Override
    public void close() {
        clear(this.rootKey);
        this.i = MIN_VALUE;
        this.pn = 0;
        this.sharedSecret.close();
        if (this.macsToReveal.size() > 0) {
            throw new IllegalStateException("BUG: Remaining MACs have not been revealed.");
        }
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
        // Perform sender key rotation.
        LOGGER.log(FINEST, "Rotating root key and sending chain key for ratchet " + this.i);
        final boolean performDHRatchet = this.i % 3 == 0;
        this.sharedSecret.rotateOurKeys(performDHRatchet);
        generateRatchetKeys(Purpose.SENDING);
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
        LOGGER.log(FINEST, "Generating message keys for encryption of ratchet {0}, message {1}.",
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
        LOGGER.log(FINEST, "Generating message keys for authentication of ratchet {0}, message {1}.",
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
     * Verify then decrypt a received OTRv4 data message.
     *
     * @param ratchetId                  ID for the receiving ratchet.
     * @param messageId                  ID for the receiving ratchet message ID.
     * @param encodedDataMessageSections Data message sections that need to be authenticated, encoded as byte-array.
     * @param ciphertext                 The encrypted message ciphertext.
     * @param nonce                      The nonce used in encryption.
     * @return Returns the decrypted ciphertext.
     * @throws VerificationException       If data message fails verification, i.e. the authenticators do not match.
     * @throws RotationLimitationException In case of failure to acquire the corresponding message keys. This exception
     *                                     occurs when the first message of a new message is missing and therefore we
     *                                     cannot generate the necessary keys.
     */
    byte[] decrypt(final int ratchetId, final int messageId, @Nonnull final byte[] encodedDataMessageSections,
            @Nonnull final byte[] authenticator, @Nonnull final byte[] ciphertext, @Nonnull final byte[] nonce)
            throws VerificationException, RotationLimitationException {
        LOGGER.log(FINEST, "Generating message keys for verification and decryption of ratchet {0}, message {1}.",
                new Object[] {this.i - 1, this.receiverRatchet.messageID});
        try (MessageKeys keys = generateReceivingKeys(ratchetId, messageId)) {
            final byte[] digest = kdf1(DATA_MESSAGE_SECTIONS, encodedDataMessageSections,
                    DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES);
            keys.verify(digest, authenticator);
            this.macsToReveal.write(authenticator, 0, authenticator.length);
            clear(digest);
            return keys.decrypt(ciphertext, nonce);
        }
    }

    /**
     * Acquire the extra symmetric key that corresponds to the next message to be sent.
     * <p>
     * Note that this is the "raw" extra symmetric key. OTRv4 specifies how one can derive additional keys from this
     * "raw" input data. These additional steps are not performed.
     *
     * @return The "raw" extra symmetric key. (User needs to clean up the byte-array after use.)
     */
    @Nonnull
    byte[] extraSymmetricSendingKey() {
        requireNotClosed();
        LOGGER.log(FINEST, "Generating extra symmetric keys for encryption of ratchet {0}, message {1}.",
                new Object[] {this.i - 1, this.senderRatchet.messageID});
        try (MessageKeys keys = generateSendingKeys()) {
            return keys.getExtraSymmetricKey();
        }
    }

    /**
     * Acquire the extra symmetric key that corresponds to received messages.
     *
     * @return The "raw" extra symmetric key. (User needs to clean up the byte-array after use.)
     */
    @Nonnull
    byte[] extraSymmetricReceivingKey(final int ratchetId, final int messageId) throws RotationLimitationException {
        requireNotClosed();
        LOGGER.log(FINEST, "Generating extra symmetric keys for encryption of ratchet {0}, message {1}.",
                new Object[] {this.i - 1, this.senderRatchet.messageID});
        try (MessageKeys keys = generateReceivingKeys(ratchetId, messageId)) {
            return keys.getExtraSymmetricKey();
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
            LOGGER.log(FINEST, "Fast-forward rotating receiving chain key to catch up with message ID: " + messageId);
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
    // FIXME need to verify that public keys (ECDH and DH) were not encountered previously.
    void rotateReceiverKeys(@Nonnull final Point nextECDH, @Nullable final BigInteger nextDH) throws OtrCryptoException {
        requireNotClosed();
        LOGGER.log(FINEST, "Rotating root key and receiving chain key for ratchet {0} (nextDH = {1})",
                new Object[]{this.i, nextDH != null});
        // FIXME do we want to check DH and ECDH public keys individually and immediately decide to return early? (or check both and only then decide)
        if (nextECDH.equals(this.sharedSecret.getTheirECDHPublicKey())) {
            LOGGER.log(FINE, "Skipping rotating receiver keys as ECDH public key is already known.");
            return;
        }
        if (nextDH != null && nextDH.equals(this.sharedSecret.getTheirDHPublicKey())) {
            LOGGER.log(FINE, "Skipping rotating receiver keys as DH public key is already known.");
            return;
        }
        final boolean performDHRatchet = this.i % 3 == 0;
        this.sharedSecret.rotateTheirKeys(performDHRatchet, nextECDH, nextDH);
        this.pn = this.senderRatchet.messageID;
        generateRatchetKeys(Purpose.RECEIVING);
        this.senderRatchet.needsRotation = true;
        this.i += 1;
    }

    private void generateRatchetKeys(@Nonnull final Purpose purpose) {
        final byte[] previousRootKey = this.rootKey.clone();
        final byte[] newK = this.sharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(previousRootKey, newK);
        kdf1(this.rootKey, 0, ROOT_KEY, concatPreviousRootKeyNewK, ROOT_KEY_LENGTH_BYTES);
        switch (purpose) {
        case SENDING:
            this.senderRatchet.rotateKeys(concatPreviousRootKeyNewK);
            break;
        case RECEIVING:
            this.receiverRatchet.rotateKeys(concatPreviousRootKeyNewK);
            break;
        default:
            throw new UnsupportedOperationException("Unsupported parameter: " + purpose);
        }
        clear(newK);
        clear(previousRootKey);
        clear(concatPreviousRootKeyNewK);
    }

    /**
     * Get the remaining MAC-keys-to-be-revealed. (And remove them from the internal list to be revealed.)
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

    /**
     * Forget the remaining MAC-keys-to-be-revealed. (This is called whenever remaining MAC keys need not be revealed
     * before actually closing.)
     */
    // TODO why can't we simply reveal the remaining MACs in a message with flag IGNORE_UNREADABLE. That way, everything is revealed.
    void forgetRemainingMACsToReveal() {
        requireNotClosed();
        this.macsToReveal.reset();
    }

    private MessageKeys generateMessageKeys(@Nonnull final byte[] chainkey) {
        assert !allZeroBytes(chainkey) : "Expected chainkey of random data instead of all zero-bytes.";
        final byte[] encrypt = kdf1(MESSAGE_KEY, chainkey, MessageKeys.MK_ENC_LENGTH_BYTES);
        final byte[] concat0xffChainKey = concatenate(new byte[] {(byte) 0xff}, chainkey);
        final byte[] extraSymmetricKey = kdf1(EXTRA_SYMMETRIC_KEY, concat0xffChainKey, MessageKeys.EXTRA_SYMMETRIC_KEY_LENGTH_BYTES);
        clear(concat0xffChainKey);
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
        private boolean needsRotation = false;

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

    /**
     * The role which is fulfilled according to the OTRv4 specification.
     */
    enum Role {
        ALICE, BOB
    }

    private enum Purpose {
        SENDING, RECEIVING
    }
}
