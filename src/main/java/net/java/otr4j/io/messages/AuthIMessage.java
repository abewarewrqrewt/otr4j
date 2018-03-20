package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.io.IOException;

import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Auth I Message.
 */
final class AuthIMessage extends AbstractEncodedMessage {

    private static final int MESSAGE_AUTH_I = 0x88;

    // FIXME add sigma (ring signature)

    AuthIMessage(final int protocolVersion, final int senderInstance, final int recipientInstance) {
        super(requireAtLeast(4, protocolVersion), senderInstance, recipientInstance);
    }

    @Override
    public void write(@Nonnull final OtrOutputStream writer) throws IOException {
        super.write(writer);
        // FIXME add sigma
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_I;
    }
}
