package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.profile.UserProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireAtLeast;

/**
 * OTRv4 Interactive DAKE Identity Message.
 *
 * The identity message is used to send initial identity information upon establishing a new session.
 */
public final class IdentityMessage extends AbstractEncodedMessage {

    // OTRv4 Encoded message types
    static final int MESSAGE_IDENTITY = 0x08;

    private final UserProfile userProfile;
    private final Point y;
    private final BigInteger b;

    // FIXME need to do additional validation for values being injected in constructor?
    public IdentityMessage(final int protocolVersion, final int senderInstance, final int receiverInstance,
                    @Nonnull final UserProfile userProfile, @Nonnull final Point y, @Nonnull final BigInteger b) {
        super(requireAtLeast(4, protocolVersion), senderInstance, receiverInstance);
        this.userProfile = requireNonNull(userProfile);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
    }

    @Override
    public int getType() {
        return MESSAGE_IDENTITY;
    }

    @Nonnull
    public UserProfile getUserProfile() {
        return userProfile;
    }

    @Nonnull
    public Point getY() {
        return y;
    }

    @Nonnull
    public BigInteger getB() {
        return b;
    }

    @Override
    public void write(@Nonnull final OtrOutputStream writer) throws IOException {
        super.write(writer);
        writer.writeUserProfile(this.userProfile);
        writer.writePoint(this.y);
        writer.writeBigInt(this.b);
    }
}
