package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Auth R Message.
 */
// FIXME write unit tests
public final class AuthRMessage extends AbstractEncodedMessage {

    static final byte MESSAGE_AUTH_R = (byte) 0x91;

    private final ClientProfilePayload clientProfile;

    private final Point x;

    private final BigInteger a;

    private final OtrCryptoEngine4.Sigma sigma;

    public AuthRMessage(final int protocolVersion, final int senderInstance, final int recipientInstance,
                        @Nonnull final ClientProfilePayload clientProfile, @Nonnull final Point x, @Nonnull final BigInteger a,
                        @Nonnull final OtrCryptoEngine4.Sigma sigma) {
        super(requireAtLeast(Session.OTRv.FOUR, protocolVersion), senderInstance, recipientInstance);
        this.clientProfile = requireNonNull(clientProfile);
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
        this.sigma = requireNonNull(sigma);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_R;
    }

    @Nonnull
    public ClientProfilePayload getClientProfile() {
        return clientProfile;
    }

    @Nonnull
    public Point getX() {
        return x;
    }

    @Nonnull
    public BigInteger getA() {
        return a;
    }

    @Nonnull
    public OtrCryptoEngine4.Sigma getSigma() {
        return sigma;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.write(this.clientProfile);
        writer.writePoint(this.x);
        writer.writeBigInt(this.a);
        writer.write(this.sigma);
    }
}
