package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DoubleRatchet;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.security.PublicKey;
import java.util.List;

import static net.java.otr4j.crypto.SharedSecret4.initialize;

/**
 * The OTRv4 ENCRYPTED message state.
 */
// FIXME handle use cases of resending Auth-I and Auth-R message in case of receiving certain messages in duplicate. (However, how does resending help for long-established encrypted sessions?)
final class StateEncrypted4 extends AbstractStateEncrypted {

    private final DoubleRatchet ratchet;

    StateEncrypted4(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) throws OtrCryptoException {
        super(context.getSessionID(), context.getHost());
        this.ratchet = new DoubleRatchet(context.secureRandom(), initialize(params));
    }

    @Override
    public int getVersion() {
        return 4;
    }

    @Nonnull
    @Override
    public SessionStatus getStatus() {
        return SessionStatus.ENCRYPTED;
    }

    @Nonnull
    @Override
    public PublicKey getRemotePublicKey() throws IncorrectStateException {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Nonnull
    @Override
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Nonnull
    @Override
    public DataMessage transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) throws OtrException {
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
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) throws IOException, OtrException {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters params) throws OtrException {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) throws OtrCryptoException {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }

    @Nonnull
    @Override
    public SmpTlvHandler getSmpTlvHandler() throws IncorrectStateException {
        // FIXME to be implemented.
        throw new UnsupportedOperationException("To be implemented.");
    }
}
