package net.java.otr4j.session.state;

import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.PublicKey;
import java.util.List;

import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.SharedSecret4.initialize;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * The OTRv4 ENCRYPTED message state.
 */
// TODO signal errors in data message using ERROR_2 indicator.
final class StateEncrypted4 extends AbstractStateEncrypted implements AutoCloseable {

    private static final int SSID_LENGTH_BYTES = 8;
    private static final byte[] USAGE_ID_SSID_GENERATION = new byte[]{0x05};

    private static final int VERSION = Session.OTRv.FOUR;

    private final byte[] ssid = new byte[SSID_LENGTH_BYTES];

    private final DoubleRatchet ratchet;

    StateEncrypted4(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) throws OtrCryptoException {
        super(context.getSessionID(), context.getHost());
        final SharedSecret4 sharedSecret = initialize(params);
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
    public DataMessage transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
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
