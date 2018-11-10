/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.io.EncryptedMessage.Content;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;
import net.java.otr4j.session.smpv4.SMP;
import net.java.otr4j.session.state.DoubleRatchet.EncryptionResult;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;
import net.java.otr4j.session.state.DoubleRatchet.RotationResult;
import net.java.otr4j.session.state.DoubleRatchet.VerificationException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Collections.singletonList;
import static net.java.otr4j.api.OtrEngineHostUtil.unencryptedMessageReceived;
import static net.java.otr4j.crypto.SharedSecret4.initialize;
import static net.java.otr4j.io.EncryptedMessage.extractContents;
import static net.java.otr4j.session.smpv4.SMP.smpPayload;

/**
 * The OTRv4 ENCRYPTED message state.
 */
// TODO signal errors in data message using ERROR_2 indicator.
final class StateEncrypted4 extends AbstractStateEncrypted implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(StateEncrypted4.class.getName());

    private static final byte DATA_MESSAGE_TYPE = 0x03;

    private static final int VERSION = Session.Version.FOUR;

    private static final byte IGNORE_UNREADABLE = 0x01;

    private final DoubleRatchet ratchet;

    private final SMP smp;

    StateEncrypted4(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) {
        super(context.getSessionID(), context.getHost());
        final byte[] exchangeK;
        final byte[] ssid;
        try (SharedSecret4 exchangeSecret = params.generateSharedSecret(context.secureRandom())) {
            ssid = exchangeSecret.generateSSID();
            exchangeK = exchangeSecret.getK();
        }
        final SharedSecret4.Rotation component;
        switch (params.getInitializationComponent()) {
        case THEIRS:
            component = SharedSecret4.Rotation.RECEIVER_KEYS;
            break;
        case OURS:
            component = SharedSecret4.Rotation.SENDER_KEYS;
            break;
        default:
            throw new UnsupportedOperationException("Unknown initialization component.");
        }
        params.close();
        final SharedSecret4 preparedSecret = initialize(context.secureRandom(), exchangeK, component);
        this.ratchet = new DoubleRatchet(context.secureRandom(), preparedSecret, exchangeK);
        this.smp = new SMP(context.secureRandom(), context.getHost(), context.getSessionID(), ssid,
                params.getOurProfile().getLongTermPublicKey(), params.getTheirProfile().getLongTermPublicKey(),
                context.getReceiverInstanceTag());
    }

    @Override
    public void close() {
        this.ratchet.close();
        this.smp.close();
    }

    @Override
    public int getVersion() {
        return VERSION;
    }

    @Nonnull
    @Override
    public SessionStatus getStatus() {
        return SessionStatus.ENCRYPTED;
    }

    @Nonnull
    @Override
    public DSAPublicKey getRemotePublicKey() {
        // TODO to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    /**
     * The extra symmetric key is the "raw" key. It does not perform the additional multi-key-derivations that are
     * described in the OTRv4 specification in case of multiple TLV 7 payloads using index and payload context (first 4
     * bytes).
     * <p>
     * The acquired extra symmetric key is the key that corresponds to the next message that is sent.
     * <p>
     * Note: the user is responsible for cleaning up the extra symmetric key material after use.
     * <p>
     * {@inheritDoc}
     */
    // FIXME write unit tests for acquisition and use of extra symmetric key
    // FIXME how to expose Extra Symmetric Key for receiving?
    @Nonnull
    @Override
    public byte[] getExtraSymmetricKey() {
        return this.ratchet.extraSymmetricSendingKey();
    }

    @Nonnull
    @Override
    public DataMessage4 transformSending(@Nonnull final Context context, @Nonnull final String msgText,
            @Nonnull final List<TLV> tlvs) {
        return transformSending(context, msgText, tlvs, (byte) 0);
    }

    private DataMessage4 transformSending(@Nonnull final Context context, @Nonnull final String msgText,
            @Nonnull final List<TLV> tlvs, final byte flags) {
        final RotationResult rotation;
        if (this.ratchet.isNeedSenderKeyRotation()) {
            rotation = this.ratchet.rotateSenderKeys();
            LOGGER.log(Level.FINEST, "Sender keys rotated. DH public key: {0}, revealed MACs size: {1}.",
                    new Object[] {rotation.dhPublicKey != null, rotation.revealedMacs.length});
        } else {
            rotation = null;
            LOGGER.log(Level.FINEST, "Sender keys rotation is not needed.");
        }
        final byte[] msgBytes = new OtrOutputStream().writeMessage(msgText).writeByte(0).writeTLV(tlvs).toByteArray();
        final EncryptionResult result = this.ratchet.encrypt(msgBytes);
        final int ratchetId = this.ratchet.getI();
        final int messageId = this.ratchet.getJ();
        final byte[] dataMessageSectionsContent = generateDataMessageContent(ratchetId, messageId,
                context.getSenderInstanceTag(), context.getReceiverInstanceTag(), rotation, result);
        final byte[] authenticator = this.ratchet.authenticate(dataMessageSectionsContent);
        this.ratchet.rotateSendingChainKey();
        return new DataMessage4(VERSION, context.getSenderInstanceTag(), context.getReceiverInstanceTag(), flags,
                this.ratchet.getPn(), ratchetId, messageId, this.ratchet.getECDHPublicKey(),
                rotation == null ? null : rotation.dhPublicKey, result.nonce, result.ciphertext, authenticator,
                rotation == null ? new byte[0] : rotation.revealedMacs);
    }

    @Nonnull
    private byte[] generateDataMessageContent(final int ratchetId, final int messageId,
            @Nonnull final InstanceTag sender, @Nonnull final InstanceTag receiver,
            @Nullable final RotationResult rotation, @Nonnull final EncryptionResult encryptionResult) {
        final OtrOutputStream out = new OtrOutputStream().writeShort(VERSION).writeByte(DATA_MESSAGE_TYPE)
                .writeInt(sender.getValue()).writeInt(receiver.getValue()).writeByte(0x00).writeInt(this.ratchet.getPn())
                .writeInt(ratchetId).writeInt(messageId).writePoint(this.ratchet.getECDHPublicKey());
        if (rotation == null || rotation.dhPublicKey == null) {
            out.writeData(new byte[0]);
        } else {
            out.writeBigInt(rotation.dhPublicKey);
        }
        return out.writeNonce(encryptionResult.nonce).writeData(encryptionResult.ciphertext).toByteArray();
    }

    @Nonnull
    @Override
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage message) {
        // Display the message to the user, but warn him that the message was received unencrypted.
        final String cleanText = message.getCleanText();
        unencryptedMessageReceived(context.getHost(), this.sessionID, cleanText);
        return cleanText;
    }

    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) {
        throw new IllegalStateException("OTRv4 encrypted message state does not handle OTRv2/OTRv3 data messages.");
    }

    // FIXME prevent case where data message arrives before first data message is sent. (Handle, signal, ...) - should fix itself once extra DAKE state is introduced.
    // FIXME write tests for SMP_ABORT sets UNREADABLE flag, SMP payload corrupted, SMP payload incomplete, ...
    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message)
            throws OtrException, ProtocolException {
        if (message.getJ() == 0) {
            if (message.getI() < this.ratchet.getI()) {
                // Ratchet ID < our current ratchet ID. This is technically impossible, so should not be supported.
                throw new ProtocolException("The double ratchet does not allow for first messages of previous ratchet ID to arrive at a later time. This is an illegal message.");
            }
            // If a new ratchet key has been received, any message keys corresponding to skipped messages from the previous
            // receiving ratchet are stored. A new DH ratchet is performed.
            // TODO generate and store skipped message for previous chain key.
            // The Double Ratchet prescribes alternate rotations, so after a single rotation for each we expect to reveal MAC codes.
            if (message.getI() > 0 && message.getRevealedMacs().length == 0) {
                assert false : "CHECK: Shouldn't there always be at least one MAC code to reveal?";
                logger.warning("Expected other party to reveal recently used MAC codes, but no MAC codes are revealed! (This may be a bug in the other party's OTR implementation.)");
            }
            this.ratchet.rotateReceiverKeys(message.getEcdhPublicKey(), message.getDhPublicKey());
        }
        // If the encrypted message corresponds to an stored message key corresponding to an skipped message, the
        // message is verified and decrypted with that key which is deleted from the storage.
        // TODO try to decrypt using skipped message keys.
        // If a new message from the current receiving ratchet is received, any message keys corresponding to skipped
        // messages from the same ratchet are stored, and a symmetric-key ratchet is performed to derive the current
        // message key and the next receiving chain key. The message is then verified and decrypted.
        final byte[] dmc;
        try {
            final OtrOutputStream out = new OtrOutputStream();
            message.writeDataMessageSections(out);
            this.ratchet.verify(message.getI(), message.getJ(), out.toByteArray(), message.getAuthenticator());
            dmc = this.ratchet.decrypt(message.getI(), message.getJ(), message.getCiphertext(), message.getNonce());
        } catch (final RotationLimitationException e) {
            LOGGER.log(Level.INFO, "Message received that is part of next ratchet. As we do not have the public keys for that ratchet yet, the message cannot be decrypted. This message is now lost.");
            return null;
        } catch (final VerificationException e) {
            LOGGER.log(Level.FINE, "Received message fails verification. Rejecting the message.");
            return null;
        }
        this.ratchet.rotateReceivingChainKey();
        // Process decrypted message contents. Extract and process TLVs.
        final Content content = extractContents(dmc);
        for (final TLV tlv : content.tlvs) {
            logger.log(Level.FINE, "Received TLV type {0}", tlv.getType());
            if (smpPayload(tlv)) {
                try {
                    final TLV response = this.smp.process(tlv);
                    if (response != null) {
                        context.injectMessage(transformSending(context, "", singletonList(response),
                                this.smp.smpAbortedTLV(response) ? IGNORE_UNREADABLE : 0));
                    }
                } catch (final ProtocolException | OtrCryptoException e) {
                    LOGGER.log(Level.WARNING, "Illegal, bad or corrupt SMP TLV encountered. Stopped processing. This may be indicative of a bad implementation of OTR at the other party.",
                            e);
                }
                continue;
            }
            switch (tlv.getType()) {
            case TLV.PADDING: // TLV0
                // nothing to do here, just ignore the padding
                break;
            case TLV.DISCONNECTED: // TLV1
                context.setState(new StateFinished(this.sessionID));
                break;
            // TODO extend with other TLVs that need to be handled. Ensure right TLV codes are used, as they are changed in OTRv4.
            default:
                logger.log(Level.INFO, "Unsupported TLV #{0} received. Ignoring.", tlv.getType());
                break;
            }
        }
        return content.message.length() > 0 ? content.message : null;
    }

    @Nonnull
    @Override
    public SMP getSmpHandler() {
        return this.smp;
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters params) {
        // TODO verify if this is correct according to OTRv4 spec once released.
        throw new IllegalStateException("Transitioning to lower protocol version ENCRYPTED message state is forbidden.");
    }

    @Override
    public void end(@Nonnull final Context context) throws OtrException {
        // Note: although we send a TLV 1 (DISCONNECT) here, we should not reveal remaining MACs.
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, new byte[0]);
        final AbstractEncodedMessage m = transformSending(context, "", singletonList(disconnectTlv));
        try {
            context.injectMessage(m);
        } finally {
            // Transitioning to PLAINTEXT state should not depend on host. Ensure we transition to PLAINTEXT even if we
            // have problems injecting the message into the transport.
            context.setState(new StatePlaintext(this.sessionID));
        }
    }
}
