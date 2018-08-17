/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.DataMessage4;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.MysteriousT;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.smp.SMException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import static java.util.Collections.singletonList;
import static net.java.otr4j.api.OtrEngineHostUtil.extraSymmetricKeyDiscovered;
import static net.java.otr4j.api.OtrEngineHostUtil.getReplyForUnreadableMessage;
import static net.java.otr4j.api.OtrEngineHostUtil.showError;
import static net.java.otr4j.api.OtrEngineHostUtil.unencryptedMessageReceived;
import static net.java.otr4j.api.OtrEngineHostUtil.unreadableMessageReceived;
import static net.java.otr4j.api.OtrPolicyUtil.allowedVersions;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesDecrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesEncrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha1Hmac;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.io.SerializationUtils.Content;
import static net.java.otr4j.io.SerializationUtils.extractContents;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * Message state in case an encrypted session is established.
 *
 * This message state is package-private as we only allow transitioning to this
 * state through the initial PLAINTEXT state.
 *
 * @author Danny van Heumen
 */
final class StateEncrypted extends AbstractStateEncrypted {

    /**
     * Active version of the protocol in use in this encrypted session.
     */
    private final int protocolVersion;

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

    StateEncrypted(@Nonnull final Context context, @Nonnull final SecurityParameters params) throws OtrCryptoException {
        super(context.getSessionID(), context.getHost());
        this.protocolVersion = params.getVersion();
        this.smpTlvHandler = new SmpTlvHandler(this, context, params.getS());
        this.remotePublicKey = params.getRemoteLongTermPublicKey();
        this.sessionKeyManager = new SessionKeyManager(context.secureRandom(), params.getLocalDHKeyPair(),
            params.getRemoteDHPublicKey());
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
    public SmpTlvHandler getSmpTlvHandler() {
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
        if (this.protocolVersion == OTRv.TWO) {
            throw new IllegalStateException("An OTR version 2 session was negotiated. The Extra Symmetric Key is not available in this version of the protocol.");
        }
        return this.sessionKeyManager.extraSymmetricKey();
    }

    @Override
    @Nonnull
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) {
        // Display the message to the user, but warn him that the message was
        // received unencrypted.
        final String cleanText = plainTextMessage.getCleanText();
        unencryptedMessageReceived(context.getHost(), this.sessionID, cleanText);
        return cleanText;
    }
    
    @Override
    @Nullable
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage data) throws OtrException, ProtocolException {
        logger.finest("Message state is ENCRYPTED. Trying to decrypt message.");
        final OtrEngineHost host = context.getHost();
        // Find matching session keys.
        final SessionKey matchingKeys;
        try {
            matchingKeys = sessionKeyManager.get(data.recipientKeyID,
                    data.senderKeyID);
        } catch (final SessionKeyManager.SessionKeyUnavailableException ex) {
            logger.finest("No matching keys found.");
            unreadableMessageReceived(host, this.sessionID);
            final String replymsg = getReplyForUnreadableMessage(host, this.sessionID, DEFAULT_REPLY_UNREADABLE_MESSAGE);
            context.injectMessage(new ErrorMessage(replymsg));
            return null;
        }

        // Verify received MAC with a locally calculated MAC.
        logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");

        final byte[] computedMAC = sha1Hmac(encode(data.getT()), matchingKeys.receivingMAC());
        if (!constantTimeEquals(computedMAC, data.mac)) {
            logger.finest("MAC verification failed, ignoring message");
            unreadableMessageReceived(host, this.sessionID);
            final String replymsg = getReplyForUnreadableMessage(host, this.sessionID, DEFAULT_REPLY_UNREADABLE_MESSAGE);
            context.injectMessage(new ErrorMessage(replymsg));
            return null;
        }

        logger.finest("Computed HmacSHA1 value matches sent one.");

        // Mark this MAC key as old to be revealed.
        matchingKeys.markUsed();
        final byte[] dmc;
        try {
            final byte[] lengthenedReceivingCtr = matchingKeys.verifyReceivingCtr(data.ctr);
            dmc = aesDecrypt(matchingKeys.receivingAESKey(), lengthenedReceivingCtr, data.encryptedMessage);
        } catch (final SessionKey.ReceivingCounterValidationFailed ex) {
            logger.log(Level.WARNING, "Receiving ctr value failed validation, ignoring message: {0}", ex.getMessage());
            showError(host, this.sessionID, "Counter value of received message failed validation.");
            context.injectMessage(new ErrorMessage("Message's counter value failed validation."));
            return null;
        }

        // Rotate keys if necessary.
        final SessionKey mostRecent = this.sessionKeyManager.getMostRecentSessionKeys();
        if (mostRecent.getLocalKeyID() == data.recipientKeyID) {
            this.sessionKeyManager.rotateLocalKeys();
        }
        if (mostRecent.getRemoteKeyID() == data.senderKeyID) {
            this.sessionKeyManager.rotateRemoteKeys(data.nextDH);
        }

        // Extract and process TLVs.
        final Content content = extractContents(dmc);
        for (final TLV tlv : content.tlvs) {
            logger.log(Level.FINE, "Received TLV type {0}", tlv.getType());
            switch (tlv.getType()) {
            case TLV.PADDING: // TLV0
                // nothing to do here, just ignore the padding
                break;
            case TLV.DISCONNECTED: // TLV1
                context.setState(new StateFinished(this.sessionID));
                break;
            case TLV.SMP1Q: //TLV7
                try {
                    this.smpTlvHandler.processTlvSMP1Q(tlv);
                } catch (final SMException e) {
                    throw new OtrException("Failed to process SMP1Q TLV.", e);
                }
                break;
            case TLV.SMP1: // TLV2
                try {
                    this.smpTlvHandler.processTlvSMP1(tlv);
                } catch (final SMException e) {
                    throw new OtrException("Failed to process SMP1 TLV.", e);
                }
                break;
            case TLV.SMP2: // TLV3
                try {
                    this.smpTlvHandler.processTlvSMP2(tlv);
                } catch (final SMException e) {
                    throw new OtrException("Failed to process SMP2 TLV.", e);
                }
                break;
            case TLV.SMP3: // TLV4
                try {
                    this.smpTlvHandler.processTlvSMP3(tlv);
                } catch (final SMException e) {
                    throw new OtrException("Failed to process SMP3 TLV.", e);
                }
                break;
            case TLV.SMP4: // TLV5
                try {
                    this.smpTlvHandler.processTlvSMP4(tlv);
                } catch (final SMException e) {
                    throw new OtrException("Failed to process SMP4 TLV.", e);
                }
                break;
            case TLV.SMP_ABORT: //TLV6
                this.smpTlvHandler.processTlvSMPAbort();
                break;
            case TLV.USE_EXTRA_SYMMETRIC_KEY:
                final byte[] key = matchingKeys.extraSymmetricKey();
                extraSymmetricKeyDiscovered(this.host, this.sessionID, content.message, key, tlv.getValue());
                break;
            default:
                logger.log(Level.INFO, "Unsupported TLV #{0} received. Ignoring.", tlv.getType());
                break;
            }
        }
        return content.message.length() > 0 ? content.message : null;
    }

    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message) {
        throw new IllegalStateException("OTRv2/OTRv3 encrypted message state does not handle OTRv4 data messages.");
    }

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage) throws OtrException {
        super.handleErrorMessage(context, errorMessage);
        final OtrPolicy policy = context.getSessionPolicy();
        if (!policy.isErrorStartAKE()) {
            return;
        }
        // Re-negotiate if we got an error and we are in ENCRYPTED message state
        logger.finest("Error message starts AKE.");
        final Set<Integer> versions = allowedVersions(policy);
        logger.finest("Sending Query");
        context.injectMessage(new QueryMessage("", versions));
    }

    @Override
    @Nonnull
    public DataMessage transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) throws OtrException {
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
        final DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.getLocalKeyPair().getPublic();

        // Calculate T.
        final MysteriousT t = new MysteriousT(this.protocolVersion, context.getSenderInstanceTag().getValue(),
                context.getReceiverInstanceTag().getValue(), (byte) 0, senderKeyID, recipientKeyID, nextDH, ctr,
                encryptedMsg);

        // Calculate T hash.
        final byte[] sendingMACKey = encryptionKeys.sendingMAC();

        logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");
        final byte[] mac = sha1Hmac(encode(t), sendingMACKey);

        // Get old MAC keys to be revealed.
        final byte[] oldKeys = this.sessionKeyManager.collectOldMacKeys();
        return new DataMessage(t, mac, oldKeys, context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue());
    }

    @Override
    public void end(@Nonnull final Context context) throws OtrException {
        // TLV 1 (Disconnect) is supposed to contain remaining MAC keys. However, as part of sending the data message,
        // we already include remaining MAC keys in the Data message itself.
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, TLV.EMPTY_BODY);
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
