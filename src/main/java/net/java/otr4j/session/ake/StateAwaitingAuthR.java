package net.java.otr4j.session.ake;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AuthIMessage;
import net.java.otr4j.io.messages.AuthRMessage;
import net.java.otr4j.profile.UserProfile;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.session.ake.SecurityParameters4.Component.OURS;

final class StateAwaitingAuthR extends AbstractAuthState {

    private final ECDHKeyPair ecdhKeyPair;
    private final DHKeyPair dhKeyPair;

    StateAwaitingAuthR(@Nonnull final ECDHKeyPair ecdhKeyPair, @Nonnull final DHKeyPair dhKeyPair) {
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
    }

    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException {
        if (!(message instanceof AuthRMessage)) {
            // FIXME what to do if unexpected message arrives?
            throw new IllegalStateException("Unexpected message received.");
        }
        return handleAuthRMessage(context, (AuthRMessage) message);
    }

    private AuthIMessage handleAuthRMessage(@Nonnull final AuthContext context, @Nonnull final AuthRMessage message) throws OtrCryptoException {
        final int receiverTagValue = context.getReceiverInstanceTag().getValue();
        final int senderTagValue = context.getSenderInstanceTag().getValue();
        final UserProfile ourUserProfile = context.getUserProfile();
        final UserProfile theirUserProfile = message.getUserProfile();
        // FIXME initialize a2 and a3 according to specs
        final byte[] t;
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), this.ecdhKeyPair, a2, a3, t);
        context.secure(new SecurityParameters4(OURS, ecdhKeyPair, dhKeyPair, message.getX(), message.getA()));
        context.setState(StateInitial.instance());
        return new AuthIMessage(Session.OTRv.FOUR, senderTagValue, receiverTagValue, sigma);
    }

    @Override
    public int getVersion() {
        return Session.OTRv.FOUR;
    }
}
