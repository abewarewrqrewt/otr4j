/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.EncryptedMessage.Content;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.io.QueryMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.MysteriousT;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.smp.SMException;
import net.java.otr4j.session.smp.SmpTlvHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Collections.singletonList;
import static java.util.logging.Level.FINE;
import static net.java.otr4j.api.OtrEngineHosts.extraSymmetricKeyDiscovered;
import static net.java.otr4j.api.OtrEngineHosts.showError;
import static net.java.otr4j.api.OtrEngineHosts.unencryptedMessageReceived;
import static net.java.otr4j.api.OtrPolicys.allowedVersions;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesDecrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesEncrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha1Hmac;
import static net.java.otr4j.io.EncryptedMessage.extractContents;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.session.smp.SmpTlvHandler.smpPayload;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * Message state in case an encrypted session is established.
 *
 * This message state is package-private as we only allow transitioning to this
 * state through the initial PLAINTEXT state.
 *
 * @author Danny van Heumen
 */
// FIXME write additional unit tests for StateEncrypted3
final class StateEncrypted3 extends AbstractCommonState implements StateEncrypted {

    /**
     * TLV 8 notifies the recipient to use the extra symmetric key to set up an
     * out-of-band encrypted connection.
     *
     * Payload:
     *  - 4-byte indication of what to use it for, e.g. file transfer, voice
     *    encryption, ...
     *  - undefined, free for use. Subsequent data might be the file name of
     *    your confidential file transfer.
     *
     * WARNING! You should NEVER send the extra symmetric key as payload inside
     * the TLV record. The recipient can already generate the extra symmetric
     * key.
     */
    private static final int USE_EXTRA_SYMMETRIC_KEY = 0x0008;

    /**
     * Active version of the protocol in use in this encrypted session.
     */
    private final int protocolVersion;

    @SuppressWarnings("PMD.LoggerIsNotStaticFinal")
    private final Logger logger;

    /**
     * The Socialist Millionaire Protocol handler.
     */
    private final SmpTlvHandler smpTlvHandler;

    /**
     * Long-term remote public key.
     */
    private final DSAPublicKey remotePublicKey;

    /**
     * Manager for session keys that are used during encrypted message state.
     */
    private final SessionKeyManager sessionKeyManager;

    StateEncrypted3(@Nonnull final Context context, @Nonnull final AuthState state, @Nonnull final SecurityParameters params) throws OtrCryptoException {
        super(state);
        final SessionID sessionID = context.getSessionID();
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.protocolVersion = params.getVersion();
        this.smpTlvHandler = new SmpTlvHandler(context.secureRandom(), sessionID, params.getRemoteLongTermPublicKey(),
                context.getReceiverInstanceTag(), context.getHost(), params.getS());
        this.remotePublicKey = params.getRemoteLongTermPublicKey();
        this.sessionKeyManager = new SessionKeyManager(context.secureRandom(), params.getLocalDHKeyPair(),
                params.getRemoteDHPublicKey());
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
        return this.protocolVersion;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return SessionStatus.ENCRYPTED;
    }

    @Override
    @Nonnull
    public SmpTlvHandler getSmpHandler() {
        return this.smpTlvHandler;
    }

    @Override
    @Nonnull
    public DSAPublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() {
        if (this.protocolVersion == Session.Version.TWO) {
            throw new UnsupportedOperationException("An OTR version 2 session was negotiated. The Extra Symmetric Key is not available in this version of the protocol.");
        }
        return this.sessionKeyManager.extraSymmetricKey();
    }

    @Nullable
    @Override
    AbstractEncodedMessage handleAKEMessage(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) {
        logger.log(FINE, " Ignoring OTRv4 DAKE message as we are in OTRv3 encrypted message state.");
        return null;
    }

    @Override
    @Nullable
    String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message)
            throws OtrException, ProtocolException {
        logger.finest("Message state is ENCRYPTED. Trying to decrypt message.");
        // Find matching session keys.
        final SessionKey matchingKeys;
        try {
            matchingKeys = sessionKeyManager.get(message.recipientKeyID, message.senderKeyID);
        } catch (final SessionKeyManager.SessionKeyUnavailableException ex) {
            logger.finest("No matching keys found.");
            handleUnreadableMessage(context, message);
            return null;
        }

        // Verify received MAC with a locally calculated MAC.
        logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");

        final byte[] computedMAC = sha1Hmac(encode(message.getT()), matchingKeys.receivingMAC());
        if (!constantTimeEquals(computedMAC, message.mac)) {
            logger.finest("MAC verification failed, ignoring message");
            handleUnreadableMessage(context, message);
            return null;
        }

        logger.finest("Computed HmacSHA1 value matches sent one.");

        // Mark this MAC key as old to be revealed.
        matchingKeys.markUsed();
        final byte[] dmc;
        try {
            final byte[] lengthenedReceivingCtr = matchingKeys.verifyReceivingCtr(message.ctr);
            dmc = aesDecrypt(matchingKeys.receivingAESKey(), lengthenedReceivingCtr, message.encryptedMessage);
        } catch (final SessionKey.ReceivingCounterValidationFailed ex) {
            logger.log(Level.WARNING, "Receiving ctr value failed validation, ignoring message: {0}", ex.getMessage());
            showError(context.getHost(), context.getSessionID(), "Counter value of received message failed validation.");
            context.injectMessage(new ErrorMessage("Message's counter value failed validation."));
            return null;
        }

        // Rotate keys if necessary.
        final SessionKey mostRecent = this.sessionKeyManager.getMostRecentSessionKeys();
        if (mostRecent.getLocalKeyID() == message.recipientKeyID) {
            this.sessionKeyManager.rotateLocalKeys();
        }
        if (mostRecent.getRemoteKeyID() == message.senderKeyID) {
            this.sessionKeyManager.rotateRemoteKeys(message.nextDH);
        }

        // Extract and process TLVs.
        final Content content = extractContents(dmc);
        for (final TLV tlv : content.tlvs) {
            logger.log(FINE, "Received TLV type {0}", tlv.type);
            if (smpPayload(tlv)) {
                try {
                    final TLV response = this.smpTlvHandler.process(tlv);
                    if (response != null) {
                        context.injectMessage(transformSending(context, "", singletonList(response), FLAG_IGNORE_UNREADABLE));
                    }
                } catch (final SMException e) {
                    this.logger.log(Level.WARNING, "Illegal, bad or corrupt SMP TLV encountered. Stopped processing. This may indicate a bad implementation of OTR at the other party.",
                            e);
                }
                continue;
            }
            switch (tlv.type) {
            case TLV.PADDING: // TLV0
                // nothing to do here, just ignore the padding
                break;
            case TLV.DISCONNECTED: // TLV1
                if (!content.message.isEmpty()) {
                    logger.warning("Expected other party to send TLV type 1 with empty human-readable message.");
                }
                context.transition(this, new StateFinished(getAuthState()));
                break;
            case USE_EXTRA_SYMMETRIC_KEY:
                final byte[] key = matchingKeys.extraSymmetricKey();
                extraSymmetricKeyDiscovered(context.getHost(), context.getSessionID(), content.message, key, tlv.value);
                break;
            default:
                logger.log(Level.INFO, "Unsupported TLV #{0} received. Ignoring.", tlv.type);
                break;
            }
        }
        return content.message.length() > 0 ? content.message : null;
    }

    @Nullable
    @Override
    String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message) {
        throw new IllegalStateException("BUG: OTRv2/OTRv3 encrypted message state does not handle OTRv4 data messages.");
    }

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage)
            throws OtrException {
        super.handleErrorMessage(context, errorMessage);
        final OtrPolicy policy = context.getSessionPolicy();
        if (!policy.isErrorStartAKE()) {
            return;
        }
        // Re-negotiate if we got an error and we are in ENCRYPTED message state
        logger.finest("Error message starts AKE.");
        final Set<Integer> versions = allowedVersions(policy);
        logger.finest("Sending Query");
        context.injectMessage(new QueryMessage(versions));
    }

    @Override
    @Nonnull
    public DataMessage transformSending(@Nonnull final Context context, @Nonnull final String msgText,
            @Nonnull final Iterable<TLV> tlvs, final byte flags) {
        final SessionID sessionID = context.getSessionID();
        logger.log(Level.FINEST, "{0} sends an encrypted message to {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        final byte[] data = new OtrOutputStream().writeMessage(msgText).writeByte(0).writeTLV(tlvs).toByteArray();

        // Get encryption keys.
        final SessionKey encryptionKeys = this.sessionKeyManager.getEncryptionSessionKeys();
        final int senderKeyID = encryptionKeys.getLocalKeyID();
        final int recipientKeyID = encryptionKeys.getRemoteKeyID();

        // Increment CTR.
        final byte[] ctr = encryptionKeys.acquireSendingCtr();

        // Encrypt message.
        logger.log(Level.FINEST, "Encrypting message with keyids (localKeyID, remoteKeyID) = ({0}, {1})",
                new Object[]{senderKeyID, recipientKeyID});
        final byte[] encryptedMsg = aesEncrypt(encryptionKeys.sendingAESKey(), ctr, data);

        // Get most recent keys to get the next D-H public key.
        final SessionKey mostRecentKeys = this.sessionKeyManager.getMostRecentSessionKeys();
        final DHPublicKey nextDH = mostRecentKeys.getLocalKeyPair().getPublic();

        // Calculate T.
        final MysteriousT t = new MysteriousT(this.protocolVersion, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), flags, senderKeyID, recipientKeyID, nextDH, ctr, encryptedMsg);

        // Calculate T hash.
        final byte[] sendingMACKey = encryptionKeys.sendingMAC();

        logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");
        final byte[] mac = sha1Hmac(encode(t), sendingMACKey);

        // Get old MAC keys to be revealed.
        final byte[] oldKeys = this.sessionKeyManager.collectOldMacKeys();
        return new DataMessage(t, mac, oldKeys, context.getSenderInstanceTag(), context.getReceiverInstanceTag());
    }

    @Override
    public void end(@Nonnull final Context context) throws OtrException {
        // The message carrying TLV 1 (Disconnect) is supposed to contain remaining MAC keys. However, as part of
        // sending the data message, we already include remaining MAC keys as part of sending the Data message.
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, TLV.EMPTY_BODY);
        final AbstractEncodedMessage m = transformSending(context, "", singletonList(disconnectTlv),
                FLAG_IGNORE_UNREADABLE);
        try {
            context.injectMessage(m);
        } finally {
            // Transitioning to PLAINTEXT state should not depend on host. Ensure we transition to PLAINTEXT even if we
            // have problems injecting the message into the transport.
            context.transition(this, new StatePlaintext(getAuthState()));
        }
    }

    @Override
    public void destroy() {
        this.smpTlvHandler.close();
        this.sessionKeyManager.close();
    }
}
