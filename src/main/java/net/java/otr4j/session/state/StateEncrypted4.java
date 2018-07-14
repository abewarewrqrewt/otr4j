package net.java.otr4j.session.state;

import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.DataMessage4;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;
import net.java.otr4j.session.state.DoubleRatchet.MessageKeys;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.PublicKey;
import java.util.List;

import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.SharedSecret4.initialize;
import static net.java.otr4j.io.SerializationUtils.convertTextToBytes;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * The OTRv4 ENCRYPTED message state.
 */
// TODO signal errors in data message using ERROR_2 indicator.
final class StateEncrypted4 extends AbstractStateEncrypted implements AutoCloseable {

    private static final int SSID_LENGTH_BYTES = 8;
    private static final byte[] USAGE_ID_SSID_GENERATION = new byte[]{0x05};
    private static final int DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES = 64;
    private static final byte[] USAGE_ID_DATA_MESSAGE_SECTIONS = new byte[]{0x19};

    // TODO duplicate information, can we simplify this without breaking all structure?
    private static final byte DATA_MESSAGE_TYPE = 0x03;

    private static final int VERSION = Session.OTRv.FOUR;

    private final byte[] ssid = new byte[SSID_LENGTH_BYTES];

    private final DoubleRatchet ratchet;

    StateEncrypted4(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) {
        super(context.getSessionID(), context.getHost());
        final SharedSecret4 sharedSecret = initialize(context.secureRandom(), params);
        kdf1(this.ssid, 0, concatenate(USAGE_ID_SSID_GENERATION, sharedSecret.getK()), SSID_LENGTH_BYTES);
        this.ratchet = new DoubleRatchet(context.secureRandom(), sharedSecret);
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
                messageMAC = kdf1(concatenate(USAGE_ID_DATA_MESSAGE_SECTIONS, out.toByteArray()),
                    DATA_MESSAGE_SECTIONS_HASH_LENGTH_BYTES);
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
//        final Point nextECDH;
//        final BigInteger nextDH;
//        this.ratchet.rotateReceiverKeys(nextECDH, nextDH);
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Nonnull
    @Override
    public SmpTlvHandler getSmpTlvHandler() {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters params) {
        throw new IllegalStateException("Transitioning to lower protocol version ENCRYPTED message state is forbidden.");
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) throws OtrCryptoException {
        // FIXME probably do not want to transition to new DAKE keys. Requires exiting ENCRYPTED_MESSAGES state first and transitioning through AKE states.
        context.setState(new StateEncrypted4(context, params));
    }
}
