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
import net.java.otr4j.io.messages.ClientProfilePayload;
import net.java.otr4j.io.messages.IdentityMessage;
import net.java.otr4j.io.messages.IdentityMessages;
import net.java.otr4j.io.messages.MysteriousT4;
import net.java.otr4j.profile.ClientProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.io.messages.AuthIMessages.validate;

/**
 * The state AWAITING_AUTH_I.
 *
 * This is a state in which Alice will be while awaiting Bob's final message.
 */
final class StateAwaitingAuthI extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingAuthI.class.getName());

    private final String queryTag;

    /**
     * Our ECDH key pair. (Its public key is also known as X.)
     */
    private final ECDHKeyPair ourECDHKeyPair;

    /**
     * Our DH key pair. (Its public key is also known as A.)
     */
    private final DHKeyPair ourDHKeyPair;

    private final Point y;

    private final BigInteger b;

    private final ClientProfilePayload ourProfile;

    private final ClientProfilePayload profileBob;

    private final InstanceTag senderTag;

    private final InstanceTag receiverTag;

    StateAwaitingAuthI(@Nonnull final String queryTag, @Nonnull final ECDHKeyPair ourECDHKeyPair,
                       @Nonnull final DHKeyPair ourDHKeyPair, @Nonnull final Point y, @Nonnull final BigInteger b,
                       @Nonnull final ClientProfilePayload ourProfile, @Nonnull final ClientProfilePayload profileBob,
                       @Nonnull final InstanceTag senderTag, @Nonnull final InstanceTag receiverTag) {
        this.queryTag = requireNonNull(queryTag);
        this.ourECDHKeyPair = requireNonNull(ourECDHKeyPair);
        this.ourDHKeyPair = requireNonNull(ourDHKeyPair);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.ourProfile = requireNonNull(ourProfile);
        this.profileBob = requireNonNull(profileBob);
        this.senderTag = requireNonNull(senderTag);
        this.receiverTag = requireNonNull(receiverTag);
    }

    @Nullable
    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message)
        throws OtrCryptoException, ClientProfilePayload.ValidationException, IdentityMessages.ValidationException {
        // FIXME need to verify protocol versions?
        if (message instanceof IdentityMessage) {
            return handleIdentityMessage(context, (IdentityMessage) message);
        }
        if (message instanceof AuthIMessage) {
            handleAuthIMessage(context, (AuthIMessage) message);
            return null;
        }
        // OTR: "Ignore the message."
        LOGGER.log(Level.INFO, "We only expect to receive an Identity message or an Auth-I message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
            message.getType());
        return null;
    }

    private AuthRMessage handleIdentityMessage(@Nonnull final AuthContext context, @Nonnull final IdentityMessage message)
        throws OtrCryptoException, ClientProfilePayload.ValidationException, IdentityMessages.ValidationException {
        IdentityMessages.validate(message);
        final ClientProfile theirNewClientProfile = message.getClientProfile().validate();
        final ClientProfilePayload profilePayload = context.getClientProfile();
        final EdDSAKeyPair longTermKeyPair = context.getLongTermKeyPair();
        // TODO should we verify that long-term key pair matches with long-term public key from user profile? (This would be an internal sanity check.)
        // Generate t value and calculate sigma based on known facts and generated t value.
        final byte[] t = MysteriousT4.encode(profilePayload, message.getClientProfile(), this.ourECDHKeyPair.getPublicKey(),
            message.getY(), this.ourDHKeyPair.getPublicKey(), message.getB(), context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue(), this.queryTag, context.getRemoteAccountID(),
            context.getLocalAccountID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), longTermKeyPair,
            theirNewClientProfile.getLongTermPublicKey(), message.getY(), t);
        // Generate response message and transition into next state.
        final AuthRMessage authRMessage = new AuthRMessage(Session.OTRv.FOUR, context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue(), context.getClientProfile(), this.ourECDHKeyPair.getPublicKey(),
            this.ourDHKeyPair.getPublicKey(), sigma);
        context.setState(new StateAwaitingAuthI(queryTag, this.ourECDHKeyPair, this.ourDHKeyPair, message.getY(),
            message.getB(), ourProfile, message.getClientProfile(), context.getSenderInstanceTag(),
            context.getReceiverInstanceTag()));
        return authRMessage;
    }

    private void handleAuthIMessage(@Nonnull final AuthContext context, @Nonnull final AuthIMessage message) throws OtrCryptoException, ClientProfilePayload.ValidationException {
        validate(message, this.queryTag, this.ourProfile, this.profileBob, this.ourECDHKeyPair.getPublicKey(),
            this.y, this.ourDHKeyPair.getPublicKey(), this.b, context.getRemoteAccountID(), context.getLocalAccountID());
        final SecurityParameters4 params = new SecurityParameters4(SecurityParameters4.Component.THEIRS,
            this.ourECDHKeyPair, this.ourDHKeyPair, this.y, this.b);
        context.secure(params);
        // FIXME consider if we should put 'setState' call in finally to ensure execution.
        // TODO should we reset state with or without preserving previous query tag?
        context.setState(StateInitial.empty());
    }

    @Override
    public int getVersion() {
        return Session.OTRv.FOUR;
    }
}
