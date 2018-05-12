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

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.session.ake.SecurityParameters4.Component.OURS;

/**
 * OTRv4 AKE state AWAITING_AUTH_R.
 */
final class StateAwaitingAuthR extends AbstractAuthState {

    private final String queryTag;

    /**
     * This is the sender's contact ID.
     * <p>
     * As AUTH_R receiver we need to verify 'sigma'. The other party is the sender of the 'sigma' value, hence the
     * sender contact ID.
     */
    private final String theirContactID;

    /**
     * This is the receiver's contact ID
     * <p>
     * As AUTH_R receiver we need to verify 'sigma'. 'sigma' contains the phi (shared session state). Hence we are the
     * receiving end in this process.
     */
    private final String ourContactID;

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
                       @Nonnull final String queryTag, @Nonnull final String theirContactID,
                       @Nonnull final String ourContactID) {
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.queryTag = requireNonNull(queryTag);
        this.theirContactID = requireNonNull(theirContactID);
        this.ourContactID = requireNonNull(ourContactID);
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
        // FIXME not sure if sender/receiver here are correctly identified.
        final InstanceTag receiverTag = context.getReceiverInstanceTag();
        final InstanceTag senderTag = context.getSenderInstanceTag();
        final UserProfile ourUserProfile = context.getUserProfile();
        // FIXME still need to verify contents of message for validity.
        {
            final byte[] t = MysteriousT4.encode(message.getUserProfile(), ourUserProfile, message.getX(),
                this.ecdhKeyPair.getPublicKey(), message.getA(), this.dhKeyPair.getPublicKey(), senderTag, receiverTag,
                this.queryTag, this.theirContactID, this.ourContactID);
            // "Verify the sigma with Ring Signature Authentication, that is sigma == RVrf({H_b, H_a, Y}, t)."
            ringVerify(context.getUserProfile().getLongTermPublicKey(), message.getUserProfile().getLongTermPublicKey(),
                this.ecdhKeyPair.getPublicKey(), message.getSigma(), t);
        }
        context.secure(new SecurityParameters4(OURS, ecdhKeyPair, dhKeyPair, message.getX(), message.getA()));
        context.setState(StateInitial.instance());
        final OtrCryptoEngine4.Sigma sigma;
        {
            final byte[] t = MysteriousT4.encode(message.getUserProfile(), ourUserProfile, message.getX(),
                this.ecdhKeyPair.getPublicKey(), message.getA(), this.dhKeyPair.getPublicKey(), senderTag, receiverTag,
                this.queryTag, this.ourContactID, this.theirContactID);
            sigma = ringSign(context.secureRandom(), this.ecdhKeyPair,
                message.getUserProfile().getLongTermPublicKey(), message.getX(), t);
        }
        // FIXME sender and receiver are probably swapped for the "sending AUTH_I message" use case.
        return new AuthIMessage(Session.OTRv.FOUR, senderTag.getValue(), receiverTag.getValue(), sigma);
    }

    @Override
    public int getVersion() {
        return Session.OTRv.FOUR;
    }
}
