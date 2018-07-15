package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.SerializationUtils.Content;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.DataMessage4;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;
import net.java.otr4j.session.state.DoubleRatchet.MessageKeys;
import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.security.PublicKey;
import java.util.List;
import java.util.logging.Level;

import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.DATA_MESSAGE_SECTIONS;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SSID;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.SharedSecret4.generateK;
import static net.java.otr4j.crypto.SharedSecret4.generateSSID;
import static net.java.otr4j.crypto.SharedSecret4.initialize;
import static net.java.otr4j.io.SerializationUtils.convertTextToBytes;
import static net.java.otr4j.io.SerializationUtils.extractContents;
import static org.bouncycastle.util.Arrays.clear;

/**
 * The OTRv4 ENCRYPTED message state.
 */
// TODO signal errors in data message using ERROR_2 indicator.
// TODO Verify that old MACs are received ... as a way to verify your own deniability property.
final class StateEncrypted4 extends AbstractStateEncrypted implements AutoCloseable {

    private static final int DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES = 64;

    // TODO duplicate information, can we simplify this without breaking all structure?
    private static final byte DATA_MESSAGE_TYPE = 0x03;

    private static final int VERSION = Session.OTRv.FOUR;

    private final byte[] ssid;

    private final DoubleRatchet ratchet;

    StateEncrypted4(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) {
        super(context.getSessionID(), context.getHost());
        this.ssid = generateSSID(context.secureRandom(), params);
        final byte[] exchangeK = generateK(context.secureRandom(), params);
        final SharedSecret4 sharedSecret = initialize(context.secureRandom(), params);
        this.ratchet = new DoubleRatchet(context.secureRandom(), sharedSecret, exchangeK);
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
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Nonnull
    @Override
    public DataMessage4 transformSending(@Nonnull final Context context, @Nonnull final String msgText,
                                                   @Nonnull final List<TLV> tlvs) {
        if (this.ratchet.isNeedSenderKeyRotation()) {
            // FIXME implement sender key rotation here
            final DoubleRatchet.Rotation rotation = this.ratchet.rotateSenderKeys();
            // FIXME implement accept and prepare revealed MACs here
        }
        final byte[] msgBytes = convertTextToBytes(msgText);
        final MessageKeys.Result result;
        final int ratchetId;
        final int messageId;
        final byte[] authenticator;
        // FIXME determine when to send new ECDH (and DH) keys. Only happens upon new rotation.
        try (final MessageKeys keys = this.ratchet.generateSendingKeys()) {
            ratchetId = keys.getRatchetId();
            messageId = keys.getMessageId();
            result = keys.encrypt(msgBytes);
            // TODO consider moving to separate method for readability
            final byte[] messageMAC;
            try (final OtrOutputStream out = new OtrOutputStream()) {
                out.writeShort(VERSION);
                out.writeByte(DATA_MESSAGE_TYPE);
                out.writeInt(context.getSenderInstanceTag().getValue());
                out.writeInt(context.getReceiverInstanceTag().getValue());
                out.writeByte(0x00);
                out.writeInt(this.ratchet.getPn());
                out.writeInt(ratchetId);
                out.writeInt(messageId);
                out.writePoint(this.ratchet.getECDHPublicKey());
                // FIXME DH public key should only be sent in some cases.
                out.writeBigInt(this.ratchet.getDHPublicKey());
                out.writeNonce(result.nonce);
                out.writeData(result.ciphertext);
                messageMAC = kdf1(DATA_MESSAGE_SECTIONS, out.toByteArray(), DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES);
            }
            authenticator = keys.authenticate(messageMAC);
        }
        // FIXME should DH public key always be included? (Or only in some cases?) (Maybe we should only acquire the public keys upon rotation, and not make them independently queryable.)
        // FIXME add revealed MACs to data message
        return new DataMessage4(VERSION, context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue(), (byte) 0x00, this.ratchet.getPn(), ratchetId, messageId,
            this.ratchet.getECDHPublicKey(), this.ratchet.getDHPublicKey(), result.nonce, result.ciphertext,
            authenticator, new byte[0]);
    }

    @Nonnull
    @Override
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) {
        throw new UnsupportedOperationException("The OTRv2/OTRv3 Data Message format is not accepted by OTRv4.");
    }

    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message)
        throws OtrException, IOException {
        // If the encrypted message corresponds to an stored message key corresponding to an skipped message, the
        // message is verified and decrypted with that key which is deleted from the storage.
        // FIXME try to decrypt using skipped message keys.
        // If a new ratchet key has been received, any message keys corresponding to skipped messages from the previous
        // receiving ratchet are stored. A new DH ratchet is performed.
        if (message.getJ() == 0 && !Points.equals(this.ratchet.getECDHPublicKey(), message.getEcdhPublicKey())
            && (message.getDhPublicKey() != null && !this.ratchet.getDHPublicKey().equals(message.getDhPublicKey()))) {
            this.ratchet.rotateReceiverKeys(message.getEcdhPublicKey(), message.getDhPublicKey());
            // FIXME execute receiver key rotation - To be continued ...
        }
        // If a new message from the current receiving ratchet is received, any message keys corresponding to skipped
        // messages from the same ratchet are stored, and a symmetric-key ratchet is performed to derive the current
        // message key and the next receiving chain key. The message is then verified and decrypted.
        final byte[] dmc;
        try (final MessageKeys keys = this.ratchet.generateReceivingKeys(message.getI(), message.getJ())) {
            final byte[] digest;
            try (final OtrOutputStream out = new OtrOutputStream()) {
                message.writeAuthenticatedMessageDigest(out);
                digest = kdf1(DATA_MESSAGE_SECTIONS, out.toByteArray(), DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES);
            }
            keys.verify(digest, message.getAuthenticator());
            dmc = keys.decrypt(message.getCiphertext(), message.getNonce());
        } catch (final MessageKeys.VerificationException e) {
            // FIXME reject message (do we need to return some error code or just ignore?)
            throw new OtrException("Failed to verify message: invalid authenticator.", e);
        }
        // Process decrypted message contents. Extract and process TLVs.
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
                // FIXME extend with other TLVs that need to be handled. Ensure right TLV codes are used, as they are changed in OTRv4.
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
}
