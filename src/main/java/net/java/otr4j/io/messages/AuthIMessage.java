package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.io.IOException;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Auth I Message.
 */
// FIXME write unit tests
public final class AuthIMessage extends AbstractEncodedMessage {

    static final int MESSAGE_AUTH_I = 0x88;

    private final OtrCryptoEngine4.Sigma sigma;

    public AuthIMessage(final int protocolVersion, final int senderInstance, final int recipientInstance,
                 @Nonnull final OtrCryptoEngine4.Sigma sigma) {
        super(requireAtLeast(Session.OTRv.FOUR, protocolVersion), senderInstance, recipientInstance);
        this.sigma = requireNonNull(sigma);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_I;
    }

    @Nonnull
    public OtrCryptoEngine4.Sigma getSigma() {
        return sigma;
    }

    @Override
    public void write(@Nonnull final OtrOutputStream writer) throws IOException {
        super.write(writer);
        this.sigma.writeTo(writer);
    }
}
