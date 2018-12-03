/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthIMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.IdentityMessages;
import net.java.otr4j.messages.ValidationException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthRMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_I;
import static net.java.otr4j.messages.MysteriousT4.encode;
import static net.java.otr4j.session.ake.SecurityParameters4.Component.OURS;

/**
 * OTRv4 AKE state AWAITING_AUTH_R.
 */
// FIXME migrate into Message State state machine.
final class StateAwaitingAuthR extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingAuthR.class.getName());

    /**
     * The identity message previously sent.
     */
    private final IdentityMessage previousMessage;

    /**
     * Our user's client profile payload.
     */
    private final ClientProfilePayload ourProfilePayload;

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
            @Nonnull final ClientProfilePayload ourProfilePayload, @Nonnull final String queryTag,
            @Nonnull final IdentityMessage previousMessage) {
        super();
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.ourProfilePayload = requireNonNull(ourProfilePayload);
        this.queryTag = requireNonNull(queryTag);
        this.previousMessage = requireNonNull(previousMessage);
    }

    @Nullable
    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message)
            throws OtrCryptoException, ValidationException {
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
            @Nonnull final IdentityMessage message) throws OtrCryptoException, ValidationException {
        final ClientProfile theirProfile = message.getClientProfile().validate();
        IdentityMessages.validate(message, theirProfile);
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
            throws OtrCryptoException, ValidationException {
        final EdDSAKeyPair ourLongTermKeyPair = context.getLongTermKeyPair();
        final ClientProfile ourClientProfile = this.ourProfilePayload.validate();
        final ClientProfile theirClientProfile = message.getClientProfile().validate();
        final SessionID sessionID = context.getSessionID();
        validate(message, this.ourProfilePayload, ourClientProfile, theirClientProfile, sessionID.getUserID(),
                sessionID.getAccountID(), this.ecdhKeyPair.getPublicKey(), this.dhKeyPair.getPublicKey(), this.queryTag);
        try {
            context.secure(new SecurityParameters4(OURS, ecdhKeyPair, dhKeyPair, message.getX(), message.getA(),
                    ourClientProfile, theirClientProfile));
        } finally {
            context.setAuthState(StateInitial.empty());
        }
        final InstanceTag senderTag = context.getSenderTag();
        final InstanceTag receiverTag = context.getReceiverTag();
        final byte[] t = encode(AUTH_I, message.getClientProfile(), this.ourProfilePayload, message.getX(),
            this.ecdhKeyPair.getPublicKey(), message.getA(), this.dhKeyPair.getPublicKey(), senderTag.getValue(),
            receiverTag.getValue(), this.queryTag, sessionID.getAccountID(), sessionID.getUserID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), ourLongTermKeyPair,
                ourLongTermKeyPair.getPublicKey(), theirClientProfile.getForgingKey(), message.getX(), t);
        return new AuthIMessage(Session.Version.FOUR, senderTag, receiverTag, sigma);
    }

    @Override
    public int getVersion() {
        return Session.Version.FOUR;
    }
}
