package net.java.otr4j.session.state;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.SerializationUtils.Content;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.DataMessage4;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;
import net.java.otr4j.session.smpv4.SMP;
import net.java.otr4j.session.state.DoubleRatchet.EncryptionResult;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;
import net.java.otr4j.session.state.DoubleRatchet.RotationResult;
import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.PublicKey;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Collections.singletonList;
import static net.java.otr4j.api.OtrEngineHostUtil.unencryptedMessageReceived;
import static net.java.otr4j.crypto.SharedSecret4.createSharedSecret;
import static net.java.otr4j.crypto.SharedSecret4.initialize;
import static net.java.otr4j.io.SerializationUtils.extractContents;
import static org.bouncycastle.util.Arrays.clear;

/**
 * The OTRv4 ENCRYPTED message state.
 */
// TODO signal errors in data message using ERROR_2 indicator.
final class StateEncrypted4 extends AbstractStateEncrypted implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(StateEncrypted4.class.getName());

    private static final byte DATA_MESSAGE_TYPE = 0x03;

    private static final int VERSION = Session.OTRv.FOUR;

    private final byte[] ssid;

    private final DoubleRatchet ratchet;

    private final SMP smp;

    StateEncrypted4(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) {
        super(context.getSessionID(), context.getHost());
        final byte[] exchangeK;
        try (SharedSecret4 exchangeSecret = createSharedSecret(context.secureRandom(), params)) {
            this.ssid = exchangeSecret.generateSSID();
            exchangeK = exchangeSecret.getK();
        }
        final SharedSecret4 preparedSecret = initialize(context.secureRandom(), exchangeK,
                params.getInitializationComponent());
        this.ratchet = new DoubleRatchet(context.secureRandom(), preparedSecret, exchangeK);
        this.smp = new SMP(context.secureRandom());
    }

    @Override
    public void close() {
        clear(this.ssid);
        this.ratchet.close();
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
    public PublicKey getRemotePublicKey() {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Nonnull
    @Override
    public byte[] getExtraSymmetricKey() {
        // FIXME Requires specific way-of-working to keep track of context information such as TLV payload and counter of extra symmetric key exposures. See https://github.com/otrv4/otrv4/blob/master/otrv4.md#extra-symmetric-key)
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Nonnull
    @Override
    public DataMessage4 transformSending(@Nonnull final Context context, @Nonnull final String msgText,
            @Nonnull final List<TLV> tlvs) {
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
        return new DataMessage4(VERSION, context.getSenderInstanceTag().getValue(),
                context.getReceiverInstanceTag().getValue(), (byte) 0x00, this.ratchet.getPn(), ratchetId, messageId,
                this.ratchet.getECDHPublicKey(), rotation == null ? null : rotation.dhPublicKey, result.nonce,
                result.ciphertext, authenticator, rotation == null ? new byte[0] : rotation.revealedMacs);
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

    // FIXME prevent case where data message arrives before first data message is sent. (Handle, signal, ...)
    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message)
            throws OtrException, ProtocolException {
        // If the encrypted message corresponds to an stored message key corresponding to an skipped message, the
        // message is verified and decrypted with that key which is deleted from the storage.
        // TODO try to decrypt using skipped message keys.
        if (message.getJ() == 0 && !Points.equals(this.ratchet.getECDHPublicKey(), message.getEcdhPublicKey())) {
            // FIXME condition above should include check on "... and the 'Public DH Key' is different from their_dh -if present-"
            // FIXME what to do if ratchetId < 'i' and messageId == 0? We shouldn't blindly start processing, but this case does not seem to be caught earlier in either implementation or spec.
            // If a new ratchet key has been received, any message keys corresponding to skipped messages from the previous
            // receiving ratchet are stored. A new DH ratchet is performed.
            // TODO generate and store skipped message for previous chain key.
            // The Double Ratchet prescribes alternate rotations, so after a single rotation for each we expect to reveal MAC codes.
            if (message.getI() > 0 && message.getRevealedMacs().length == 0) {
                assert false : "CHECK: Shouldn't there always be at least one MAC code to reveal?";
                logger.warning("Expected other party to reveal recently used MAC codes, but no MAC codes are revealed! (This may be a bug in the other party's OTR implementation.)");
            }
            // TODO verify that we indeed do not care about equality of DH public keys
            this.ratchet.rotateReceiverKeys(message.getEcdhPublicKey(), message.getDhPublicKey());
        }
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
            // TODO check with spec if there is a way to resolve this limitation. (Or to handle it earlier in the process in order to prevent this exception.)
            throw new OtrException("Message cannot be processed as key material for next ratchet is still missing.", e);
        } catch (final DoubleRatchet.VerificationException e) {
            // FIXME check with spec if there is a way to resolve this limitation. (Or to handle it earlier in the process in order to prevent this exception.)
            throw new OtrException("Message has failed verification.", e);
        }
        this.ratchet.rotateReceivingChainKey();
        // Process decrypted message contents. Extract and process TLVs.
        final Content content = extractContents(dmc);
        for (final TLV tlv : content.tlvs) {
            logger.log(Level.FINE, "Received TLV type {0}", tlv.getType());
            switch (tlv.getType()) {
            case TLV.PADDING: // TLV0
                // nothing to do here, just ignore the padding
                break;
            case TLV.DISCONNECTED: // TLV1
                // FIXME shouldn't we send remaining MACs-to-be-revealed here? (Not sure if this is specified in OTRv3 or OTRv4.)
                context.setState(new StateFinished(this.sessionID));
                break;
            case TLV.SMP1:
            case TLV.SMP2:
            case TLV.SMP3:
            case TLV.SMP4:
                final TLV response = this.smp.process(tlv);
                if (response != null) {
                    context.injectMessage(transformSending(context, "", singletonList(response)));
                }
                break;
            case TLV.SMP_ABORT:
                this.smp.abort();
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
    public SmpTlvHandler getSmpTlvHandler() {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters params) {
        // TODO verify if this is correct according to OTRv4 spec once released.
        throw new IllegalStateException("Transitioning to lower protocol version ENCRYPTED message state is forbidden.");
    }

    // FIXME Verify in test that indeed MACs are correctly revealed.
    @Override
    public void end(@Nonnull final Context context) throws OtrException {
        // Determine whether or not we need to add MACs to be revealed. If we are intending to rotate, there is no need
        // to add the MAC keys here.
        final byte[] revealedMACs = this.ratchet.isNeedSenderKeyRotation() ? TLV.EMPTY_BODY
            : this.ratchet.collectRemainingMACsToReveal();
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, revealedMACs);
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
