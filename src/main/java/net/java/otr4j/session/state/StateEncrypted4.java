/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncryptedMessage.Content;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.smpv4.SMP;
import net.java.otr4j.session.state.DoubleRatchet.EncryptionResult;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;
import net.java.otr4j.session.state.DoubleRatchet.RotationResult;
import net.java.otr4j.session.state.DoubleRatchet.VerificationException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.util.logging.Logger;

import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.OtrEngineHosts.unencryptedMessageReceived;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.TLV.DISCONNECTED;
import static net.java.otr4j.io.EncryptedMessage.extractContents;
import static net.java.otr4j.messages.DataMessage4s.encodeDataMessageSections;
import static net.java.otr4j.session.smpv4.SMP.smpPayload;

/**
 * The OTRv4 ENCRYPTED_MESSAGES state.
 */
// TODO signal errors in data message using ERROR_2 indicator.
// FIXME write additional unit tests for StateEncrypted4
// TODO decide whether or not we can drop the AuthState instance. Relies on fact that we need to know up to what point we should handle OTRv2/3 AKE messages.
final class StateEncrypted4 extends AbstractCommonState implements StateEncrypted {

    private static final int VERSION = FOUR;

    @SuppressWarnings("PMD.LoggerIsNotStaticFinal")
    private final Logger logger;

    private final DoubleRatchet ratchet;

    private final SMP smp;

    StateEncrypted4(@Nonnull final Context context, @Nonnull final byte[] ssid,
            @Nonnull final Point ourLongTermPublicKey, @Nonnull final Point theirLongTermPublicKey,
            @Nonnull final DoubleRatchet ratchet, @Nonnull final AuthState authState) {
        super(authState);
        final SessionID sessionID = context.getSessionID();
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.ratchet = requireNonNull(ratchet);
        this.smp = new SMP(context.secureRandom(), context.getHost(), sessionID, ssid, ourLongTermPublicKey,
                theirLongTermPublicKey, context.getReceiverInstanceTag());
    }

    @Nonnull
    @Override
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage message) {
        // Display the message to the user, but warn him that the message was received unencrypted.
        unencryptedMessageReceived(context.getHost(), context.getSessionID(), message.getCleanText());
        return super.handlePlainTextMessage(context, message);
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
        // FIXME to be implemented.
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
            @Nonnull final Iterable<TLV> tlvs, final byte flags) {
        final RotationResult rotation;
        if (this.ratchet.isNeedSenderKeyRotation()) {
            rotation = this.ratchet.rotateSenderKeys();
            this.logger.log(FINEST, "Sender keys rotated. DH public key: {0}, revealed MACs size: {1}.",
                    new Object[] {rotation.dhPublicKey != null, rotation.revealedMacs.length});
        } else {
            rotation = null;
            this.logger.log(FINEST, "Sender keys rotation is not needed.");
        }
        final byte[] msgBytes = new OtrOutputStream().writeMessage(msgText).writeByte(0).writeTLV(tlvs).toByteArray();
        final EncryptionResult result = this.ratchet.encrypt(msgBytes);
        final int ratchetId = this.ratchet.getI();
        final int messageId = this.ratchet.getJ();
        final DataMessage4 unauthenticated = new DataMessage4(VERSION, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), flags, this.ratchet.getPn(), ratchetId, messageId,
                this.ratchet.getECDHPublicKey(), rotation == null ? null : rotation.dhPublicKey, result.nonce,
                result.ciphertext, new byte[64], rotation == null ? new byte[0] : rotation.revealedMacs);
        final byte[] authenticator = this.ratchet.authenticate(encodeDataMessageSections(unauthenticated));
        this.ratchet.rotateSendingChainKey();
        return new DataMessage4(unauthenticated, authenticator);
    }

    @Nullable
    @Override
    AbstractEncodedMessage handleAKEMessage(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) {
        if (message instanceof IdentityMessage) {
            try {
                return handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final ValidationException e) {
                logger.log(INFO, "Failed to process Identity message.", e);
                return null;
            }
        }
        logger.log(INFO, "We only expect to receive an Identity message. Ignoring message with messagetype: {0}",
                message.getType());
        return null;
    }

    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) {
        throw new IllegalStateException("BUG: OTRv4 encrypted message state does not handle OTRv2/OTRv3 data messages.");
    }

    // FIXME handle case where first data messages (Data messages with ratchet id 0) arrive before very first message is received, hence Double Ratchet not yet fully initialized. (Redesigned Double Ratchet init mentions something about keeping messages for something like 50 minutes, until DAKE is completed.)
    // FIXME write tests for SMP_ABORT sets UNREADABLE flag, SMP payload corrupted, SMP payload incomplete, ...
    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message)
            throws OtrException, ProtocolException {
        if (message.j == 0) {
            if (message.i < this.ratchet.getI()) {
                // Ratchet ID < our current ratchet ID. This is technically impossible, so should not be supported.
                throw new ProtocolException("The double ratchet does not allow for first messages of previous ratchet ID to arrive at a later time. This is an illegal message.");
            }
            // If a new ratchet key has been received, any message keys corresponding to skipped messages from the previous
            // receiving ratchet are stored. A new DH ratchet is performed.
            // TODO generate and store skipped message for previous chain key.
            // The Double Ratchet prescribes alternate rotations, so after a single rotation for each we expect to reveal MAC codes.
            if (message.i > 0 && message.revealedMacs.length == 0) {
                assert false : "CHECK: Shouldn't there always be at least one MAC code to reveal?";
                logger.warning("Expected other party to reveal recently used MAC codes, but no MAC codes are revealed! (This may be a bug in the other party's OTR implementation.)");
            }
            this.ratchet.rotateReceiverKeys(message.ecdhPublicKey, message.dhPublicKey);
        }
        // If the encrypted message corresponds to an stored message key corresponding to an skipped message, the
        // message is verified and decrypted with that key which is deleted from the storage.
        // TODO try to decrypt using skipped message keys.
        // If a new message from the current receiving ratchet is received, any message keys corresponding to skipped
        // messages from the same ratchet are stored, and a symmetric-key ratchet is performed to derive the current
        // message key and the next receiving chain key. The message is then verified and decrypted.
        final byte[] dmc;
        try {
            dmc = this.ratchet.decrypt(message.i, message.j, encodeDataMessageSections(message), message.authenticator,
                    message.ciphertext, message.nonce);
        } catch (final RotationLimitationException e) {
            this.logger.log(INFO, "Message received that is part of next ratchet. As we do not have the public keys for that ratchet yet, the message cannot be decrypted. This message is now lost.");
            handleUnreadableMessage(context, message);
            return null;
        } catch (final VerificationException e) {
            this.logger.log(FINE, "Received message fails verification. Rejecting the message.");
            handleUnreadableMessage(context, message);
            return null;
        }
        this.ratchet.rotateReceivingChainKey();
        // Process decrypted message contents. Extract and process TLVs.
        final Content content = extractContents(dmc);
        for (final TLV tlv : content.tlvs) {
            logger.log(FINE, "Received TLV type {0}", tlv.type);
            if (smpPayload(tlv)) {
                if ((message.flags & FLAG_IGNORE_UNREADABLE) != FLAG_IGNORE_UNREADABLE) {
                    logger.log(WARNING, "Other party is using a faulty OTR client: all SMP messages are expected to have the IGNORE_UNREADABLE flag set.");
                }
                try {
                    final TLV response = this.smp.process(tlv);
                    if (response != null) {
                        context.injectMessage(transformSending(context, "", singletonList(response), FLAG_IGNORE_UNREADABLE));
                    }
                } catch (final ProtocolException | OtrCryptoException e) {
                    this.logger.log(WARNING, "Illegal, bad or corrupt SMP TLV encountered. Stopped processing. This may indicate a bad implementation of OTR at the other party.",
                            e);
                }
                continue;
            }
            switch (tlv.type) {
            case TLV.PADDING: // TLV0
                // nothing to do here, just ignore the padding
                break;
            case DISCONNECTED: // TLV1
                if ((message.flags & FLAG_IGNORE_UNREADABLE) != FLAG_IGNORE_UNREADABLE) {
                    logger.log(WARNING, "Other party is using a faulty OTR client: DISCONNECT messages are expected to have the IGNORE_UNREADABLE flag set.");
                }
                if (!content.message.isEmpty()) {
                    logger.warning("Expected other party to send TLV type 1 with empty human-readable message.");
                }
                this.ratchet.forgetRemainingMACsToReveal();
                context.transition(this, new StateFinished(getAuthState()));
                break;
            default:
                logger.log(INFO, "Unsupported TLV #{0} received. Ignoring.", tlv.type);
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
    public void end(@Nonnull final Context context) throws OtrException {
        // Note: although we send a TLV 1 (DISCONNECT) here, we should not reveal remaining MACs.
        final TLV disconnectTlv = new TLV(DISCONNECTED, new byte[0]);
        final AbstractEncodedMessage m = transformSending(context, "", singletonList(disconnectTlv), FLAG_IGNORE_UNREADABLE);
        try {
            context.injectMessage(m);
        } finally {
            // Transitioning to PLAINTEXT state should not depend on host. Ensure we transition to PLAINTEXT even if we
            // have problems injecting the message into the transport.
            context.transition(this, new StatePlaintext(getAuthState()));
        }
    }

    // FIXME write test for session expiration in StateEncrypted4. Needs to send message with FLAG_IGNORE_UNREADABLE, TLV, clearing, etc.
    @Override
    public void expire(@Nonnull final Context context) throws OtrException {
        final byte[] macsToReveal = this.ratchet.collectRemainingMACsToReveal();
        final TLV disconnectTlv = new TLV(DISCONNECTED, macsToReveal);
        final DataMessage4 m = transformSending(context, "", singletonList(disconnectTlv), FLAG_IGNORE_UNREADABLE);
        try {
            context.injectMessage(m);
        } finally {
            context.transition(this, new StatePlaintext(getAuthState()));
        }
    }

    @Override
    public void destroy() {
        this.ratchet.close();
        this.smp.close();
    }

    @Override
    public long getLastActivity() {
        return this.ratchet.getLastRotation();
    }
}
