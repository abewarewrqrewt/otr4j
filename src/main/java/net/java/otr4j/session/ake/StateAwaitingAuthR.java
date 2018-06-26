package net.java.otr4j.session.ake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AuthIMessage;
import net.java.otr4j.io.messages.AuthRMessage;
import net.java.otr4j.io.messages.AuthRMessages;
import net.java.otr4j.io.messages.ClientProfilePayload;
import net.java.otr4j.io.messages.IdentityMessage;
import net.java.otr4j.io.messages.IdentityMessages;
import net.java.otr4j.io.messages.MysteriousT4;
import net.java.otr4j.profile.ClientProfile;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.io.messages.AuthRMessages.validate;
import static net.java.otr4j.session.ake.SecurityParameters4.Component.OURS;

/**
 * OTRv4 AKE state AWAITING_AUTH_R.
 */
final class StateAwaitingAuthR extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingAuthR.class.getName());

    /**
     * The identity message previously sent.
     */
    private final IdentityMessage previousMessage;

    /**
     * The query tag that triggered this AKE. The query tag is part of the shared session state common knowledge that is
     * verified.
     */
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
                       @Nonnull final String queryTag, @Nonnull final IdentityMessage previousMessage) {
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.queryTag = requireNonNull(queryTag);
        this.previousMessage = requireNonNull(previousMessage);
    }

    @Nullable
    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message)
        throws OtrCryptoException, ClientProfilePayload.ValidationException, IdentityMessages.ValidationException,
        AuthRMessages.ValidationException {
        // FIXME need to verify protocol versions?
        if (message instanceof IdentityMessage) {
            return handleIdentityMessage(context, (IdentityMessage) message);
        }
        if (message instanceof AuthRMessage) {
            return handleAuthRMessage(context, (AuthRMessage) message);
        }
        // OTR: "Ignore the message."
        LOGGER.log(Level.INFO, "We only expect to receive an Identity message or an Auth-I message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
            message.getType());
        return null;
    }

    @Nullable
    private AbstractEncodedMessage handleIdentityMessage(@Nonnull final AuthContext context,
                                                         @Nonnull final IdentityMessage message)
        throws OtrCryptoException, ClientProfilePayload.ValidationException, IdentityMessages.ValidationException {
        IdentityMessages.validate(message);
        if (this.previousMessage.getB().compareTo(message.getB()) > 0) {
            // No state change necessary, we assume that by resending other party will still follow existing protocol
            // execution.
            return this.previousMessage;
        }
        // Pretend we are still in initial state and handle Identity message accordingly.
        return new StateInitial(this.queryTag).handle(context, message);
    }

    @Nonnull
    private AuthIMessage handleAuthRMessage(@Nonnull final AuthContext context, @Nonnull final AuthRMessage message)
        throws OtrCryptoException, AuthRMessages.ValidationException, ClientProfilePayload.ValidationException {
        // FIXME not sure if sender/receiver here are correctly identified. (Check also occurrence for sending next message.)
        final ClientProfilePayload ourClientProfile = context.getClientProfile();
        final EdDSAKeyPair ourLongTermKeyPair = context.getLongTermKeyPair();
        validate(message, ourClientProfile, context.getRemoteAccountID(), context.getLocalAccountID(),
            this.ecdhKeyPair.getPublicKey(), this.dhKeyPair.getPublicKey(), this.queryTag);
        // FIXME verification is currently non-functional, fix it!
        final ClientProfile theirClientProfile = message.getClientProfile().validate();
        context.secure(new SecurityParameters4(OURS, ecdhKeyPair, dhKeyPair, message.getX(), message.getA()));
        // FIXME consider if we should put 'setState' call in finally to ensure execution.
        // TODO should we preserve the most recent query tag or start with empty initial state?
        context.setState(StateInitial.empty());
        final InstanceTag senderTag = context.getSenderInstanceTag();
        final InstanceTag receiverTag = context.getReceiverInstanceTag();
        final byte[] t = MysteriousT4.encode(message.getClientProfile(), ourClientProfile, message.getX(),
            this.ecdhKeyPair.getPublicKey(), message.getA(), this.dhKeyPair.getPublicKey(), senderTag.getValue(),
            receiverTag.getValue(), this.queryTag, context.getLocalAccountID(), context.getRemoteAccountID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), ourLongTermKeyPair,
            theirClientProfile.getLongTermPublicKey(), message.getX(), t);
        // FIXME sender and receiver are probably swapped for the "sending AUTH_I message" use case.
        return new AuthIMessage(Session.OTRv.FOUR, senderTag.getValue(), receiverTag.getValue(), sigma);
    }

    @Override
    public int getVersion() {
        return Session.OTRv.FOUR;
    }
}
