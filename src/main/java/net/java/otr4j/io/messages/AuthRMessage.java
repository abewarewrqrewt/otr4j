package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.profile.UserProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Auth R Message.
 */
// FIXME write unit tests
public final class AuthRMessage extends AbstractEncodedMessage {

    static final int MESSAGE_AUTH_R = 0x91;

    private final UserProfile userProfile;

    private final Point x;

    private final BigInteger a;

    private final OtrCryptoEngine4.Sigma sigma;

    public AuthRMessage(final int protocolVersion, final int senderInstance, final int recipientInstance,
                 @Nonnull final UserProfile userProfile, @Nonnull final Point x, @Nonnull final BigInteger a,
                 @Nonnull final OtrCryptoEngine4.Sigma sigma) {
        super(requireAtLeast(Session.OTRv.FOUR, protocolVersion), senderInstance, recipientInstance);
        this.userProfile = requireNonNull(userProfile);
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
        this.sigma = requireNonNull(sigma);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_R;
    }

    @Nonnull
    public UserProfile getUserProfile() {
        return userProfile;
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
    public void write(@Nonnull final OtrOutputStream writer) throws IOException {
        super.write(writer);
        writer.writeUserProfile(this.userProfile);
        writer.writePoint(this.x);
        writer.writeBigInt(this.a);
        this.sigma.writeTo(writer);
    }
}