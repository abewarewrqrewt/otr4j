package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.io.IOException;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Auth I Message.
 */
final class AuthIMessage extends AbstractEncodedMessage {

    private static final int MESSAGE_AUTH_I = 0x88;

    private final OtrCryptoEngine4.Sigma sigma;

    AuthIMessage(final int protocolVersion, final int senderInstance, final int recipientInstance,
                 @Nonnull final OtrCryptoEngine4.Sigma sigma) {
        super(requireAtLeast(4, protocolVersion), senderInstance, recipientInstance);
        this.sigma = requireNonNull(sigma);
    }

    @Override
    public void write(@Nonnull final OtrOutputStream writer) throws IOException {
        super.write(writer);
        this.sigma.writeTo(writer);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_I;
    }
}
