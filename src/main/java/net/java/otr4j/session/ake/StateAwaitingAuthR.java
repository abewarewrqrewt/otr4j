package net.java.otr4j.session.ake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AuthIMessage;
import net.java.otr4j.io.messages.AuthRMessage;
import net.java.otr4j.io.messages.MysteriousT4;
import net.java.otr4j.profile.UserProfile;
import net.java.otr4j.profile.UserProfiles;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.io.messages.AuthRMessages.verify;
import static net.java.otr4j.session.ake.SecurityParameters4.Component.OURS;

/**
 * OTRv4 AKE state AWAITING_AUTH_R.
 */
final class StateAwaitingAuthR extends AbstractAuthState {

    private final String queryTag;

    /**
     * Our ECDH key pair.
     * <p>
     * The public key from this key pair is also known as 'y'.
     */
    private final ECDHKeyPair ecdhKeyPair;

    /**
     * Our DH key pair.
     * <p>
     * The public key from this key pair is also known as 'b'.
     */
    private final DHKeyPair dhKeyPair;

    StateAwaitingAuthR(@Nonnull final ECDHKeyPair ecdhKeyPair, @Nonnull final DHKeyPair dhKeyPair,
                       @Nonnull final String queryTag) {
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.queryTag = requireNonNull(queryTag);
    }

    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException, UserProfiles.InvalidUserProfileException {
        if (!(message instanceof AuthRMessage)) {
            // FIXME what to do if unexpected message arrives?
            throw new IllegalStateException("Unexpected message received.");
        }
        return handleAuthRMessage(context, (AuthRMessage) message);
    }

    private AuthIMessage handleAuthRMessage(@Nonnull final AuthContext context, @Nonnull final AuthRMessage message)
        throws OtrCryptoException, UserProfiles.InvalidUserProfileException {
        // FIXME not sure if sender/receiver here are correctly identified. (Check also occurrence for sending next message.)
        final InstanceTag receiverTag = context.getReceiverInstanceTag();
        final InstanceTag senderTag = context.getSenderInstanceTag();
        final UserProfile ourUserProfile = context.getUserProfile();
        verify(message, ourUserProfile, senderTag, receiverTag, context.getRemoteAccountID(),
            context.getLocalAccountID(), this.ecdhKeyPair.getPublicKey(), this.dhKeyPair.getPublicKey(), this.queryTag);
        context.secure(new SecurityParameters4(OURS, ecdhKeyPair, dhKeyPair, message.getX(), message.getA()));
        context.setState(StateInitial.instance());
        final byte[] t = MysteriousT4.encode(message.getUserProfile(), ourUserProfile, message.getX(),
            this.ecdhKeyPair.getPublicKey(), message.getA(), this.dhKeyPair.getPublicKey(), senderTag, receiverTag,
            this.queryTag, context.getLocalAccountID(), context.getRemoteAccountID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), this.ecdhKeyPair,
            message.getUserProfile().getLongTermPublicKey(), message.getX(), t);
        // FIXME sender and receiver are probably swapped for the "sending AUTH_I message" use case.
        return new AuthIMessage(Session.OTRv.FOUR, senderTag.getValue(), receiverTag.getValue(), sigma);
    }

    @Override
    public int getVersion() {
        return Session.OTRv.FOUR;
    }
}
