package net.java.otr4j.io.messages;

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
final class AuthRMessage extends AbstractEncodedMessage {

    private static final int MESSAGE_AUTH_R = 0x91;

    private final UserProfile userProfile;

    private final Point x;

    private final BigInteger a;

    private final OtrCryptoEngine4.Sigma sigma;

    AuthRMessage(final int protocolVersion, final int senderInstance, final int recipientInstance,
                 @Nonnull final UserProfile userProfile, @Nonnull final Point x, @Nonnull final BigInteger a,
                 @Nonnull final OtrCryptoEngine4.Sigma sigma) {
        super(requireAtLeast(4, protocolVersion), senderInstance, recipientInstance);
        this.userProfile = requireNonNull(userProfile);
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
        this.sigma = requireNonNull(sigma);
    }

    @Override
    public void write(@Nonnull final OtrOutputStream writer) throws IOException {
        super.write(writer);
        writer.writeUserProfile(this.userProfile);
        writer.writePoint(this.x);
        writer.writeBigInt(this.a);
        this.sigma.writeTo(writer);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_R;
    }
}
