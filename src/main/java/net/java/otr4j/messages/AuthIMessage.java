package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireInRange;

/**
 * OTRv4 Interactive DAKE Auth I Message.
 */
public final class AuthIMessage extends AbstractEncodedMessage {

    static final byte MESSAGE_AUTH_I = (byte) 0x37;

    private final Sigma sigma;

    /**
     * Constructor for Auth-I message.
     *
     * @param protocolVersion   the protocol version
     * @param senderInstance    the sender instance tag
     * @param receiverInstance the receiver instance tag
     * @param sigma             the ring signature
     */
    public AuthIMessage(final int protocolVersion, @Nonnull final InstanceTag senderInstance,
            @Nonnull final InstanceTag receiverInstance, @Nonnull final Sigma sigma) {
        super(requireInRange(OTRv.FOUR, OTRv.FOUR, protocolVersion), senderInstance, receiverInstance);
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
    public Sigma getSigma() {
        return sigma;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.write(this.sigma);
    }
}
