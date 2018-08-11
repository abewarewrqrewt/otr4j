package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Auth I Message.
 */
// FIXME write unit tests
public final class AuthIMessage extends AbstractEncodedMessage {

    static final byte MESSAGE_AUTH_I = (byte) 0x88;

    private final OtrCryptoEngine4.Sigma sigma;

    /**
     * Constructor for Auth-I message.
     *
     * @param protocolVersion   the protocol version
     * @param senderInstance    the sender instance tag
     * @param recipientInstance the receiver instance tag
     * @param sigma             the ring signature
     */
    public AuthIMessage(final int protocolVersion, final int senderInstance, final int recipientInstance,
                        @Nonnull final OtrCryptoEngine4.Sigma sigma) {
        super(requireAtLeast(Session.OTRv.FOUR, protocolVersion), senderInstance, recipientInstance);
        this.sigma = requireNonNull(sigma);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_I;
    }

    /**
     * Get the ring signature (sigma).
     *
     * @return Returns sigma.
     */
    @Nonnull
    public OtrCryptoEngine4.Sigma getSigma() {
        return sigma;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.write(this.sigma);
    }
}
