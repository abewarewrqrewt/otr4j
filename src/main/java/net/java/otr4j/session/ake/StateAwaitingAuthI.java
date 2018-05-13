package net.java.otr4j.session.ake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AuthIMessage;
import net.java.otr4j.profile.UserProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.math.BigInteger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.io.messages.AuthIMessages.validate;

/**
 * The state AWAITING_AUTH_I.
 *
 * This is a state in which Alice will be while awaiting Bob's final message.
 */
final class StateAwaitingAuthI extends AbstractAuthState {

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

    private final UserProfile ourProfile;

    private final UserProfile profileBob;

    private final InstanceTag senderTag;

    private final InstanceTag receiverTag;

    StateAwaitingAuthI(@Nonnull final String queryTag, @Nonnull final ECDHKeyPair ourECDHKeyPair,
                       @Nonnull final DHKeyPair ourDHKeyPair, @Nonnull final Point y, @Nonnull final BigInteger b,
                       @Nonnull final UserProfile ourProfile, @Nonnull final UserProfile profileBob,
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
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException {
        if (!(message instanceof AuthIMessage)) {
            // FIXME how to handle unexpected message type?
            throw new IllegalStateException("Unexpected message type.");
        }
        handleAuthIMessage(context, (AuthIMessage) message);
        return null;
    }

    private void handleAuthIMessage(@Nonnull final AuthContext context, @Nonnull final AuthIMessage message) throws OtrCryptoException {
        validate(message, this.queryTag, this.ourProfile, this.profileBob, this.ourECDHKeyPair.getPublicKey(),
            this.y, this.ourDHKeyPair.getPublicKey(), this.b, this.senderTag, this.receiverTag,
            context.getRemoteAccountID(), context.getLocalAccountID());
        final SecurityParameters4 params = new SecurityParameters4(SecurityParameters4.Component.THEIRS,
            this.ourECDHKeyPair, this.ourDHKeyPair, this.y, this.b);
        context.secure(params);
        // FIXME consider if we should put 'setState' call in finally to ensure execution.
        context.setState(StateInitial.empty());
    }

    @Override
    public int getVersion() {
        return Session.OTRv.FOUR;
    }
}
