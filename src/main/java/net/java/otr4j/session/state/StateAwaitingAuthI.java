/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthIMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.IdentityMessages;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthIMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;
import static net.java.otr4j.session.state.SecurityParameters4.Component.THEIRS;

/**
 * The state AWAITING_AUTH_I.
 *
 * This is a state in which Alice will be while awaiting Bob's final message.
 */
// TODO check OTRv4 spec for instructions on temporarily storing recently received messages while negotiating.
final class StateAwaitingAuthI extends AbstractCommonState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingAuthI.class.getName());

    /**
     * The query tag in use at the time DAKE was initiated.
     */
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

    StateAwaitingAuthI(@Nonnull final AuthState authState, @Nonnull final String queryTag,
            @Nonnull final ECDHKeyPair ourECDHKeyPair, @Nonnull final DHKeyPair ourDHKeyPair, @Nonnull final Point y,
            @Nonnull final BigInteger b, @Nonnull final ClientProfilePayload ourProfile,
            @Nonnull final ClientProfilePayload profileBob) {
        super(authState);
        this.queryTag = requireNonNull(queryTag);
        this.ourECDHKeyPair = requireNonNull(ourECDHKeyPair);
        this.ourDHKeyPair = requireNonNull(ourDHKeyPair);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.ourProfile = requireNonNull(ourProfile);
        this.profileBob = requireNonNull(profileBob);
    }

    @Override
    public int getVersion() {
        return FOUR;
    }

    @Nonnull
    @Override
    public SessionStatus getStatus() {
        return PLAINTEXT;
    }

    @Nonnull
    @Override
    public DSAPublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available until encrypted session is fully established.");
    }

    @Nonnull
    @Override
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available until encrypted session is fully established.");
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available until encrypted session is fully established.");
    }

    @Nullable
    @Override
    AbstractEncodedMessage handleAKEMessage(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) {
        if (message instanceof IdentityMessage) {
            try {
                return handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(INFO, "Failed to process Identity message.", e);
                return null;
            }
        }
        if (message instanceof AuthIMessage) {
            try {
                handleAuthIMessage(context, (AuthIMessage) message);
                return null;
            } catch (final ValidationException e) {
                LOGGER.log(WARNING, "Failed to process Auth-I message.", e);
                return null;
            }
        }
        // OTR: "Ignore the message."
        LOGGER.log(INFO, "We only expect to receive an Identity message or an Auth-I message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
        return null;
    }

    /**
     * Handle Identity message.
     * <p>
     * This implementation deviates from the implementation in StateInitial as we reuse previously generated variables.
     * Effectively it is a short-hand, because we, the local user, does not have to start from scratch.
     *
     * @param message the identity message
     * @return Returns the Auth-R message to send
     * @throws ValidationException In case of failure to validate other party's identity message or client profile.
     */
    @Nonnull
    @Override
    AuthRMessage handleIdentityMessage(@Nonnull final Context context, @Nonnull final IdentityMessage message)
            throws ValidationException {
        final ClientProfile theirNewClientProfile = message.getClientProfile().validate();
        IdentityMessages.validate(message, theirNewClientProfile);
        final SessionID sessionID = context.getSessionID();
        // Note: we query the context for a new client profile, because we're responding to a new Identity message.
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final EdDSAKeyPair longTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        // Generate t value and calculate sigma based on known facts and generated t value.
        final byte[] t = encode(AUTH_R, profilePayload, message.getClientProfile(), this.ourECDHKeyPair.getPublicKey(),
            message.getY(), this.ourDHKeyPair.getPublicKey(), message.getB(), context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue(), this.queryTag, sessionID.getUserID(), sessionID.getAccountID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), longTermKeyPair,
                theirNewClientProfile.getForgingKey(), longTermKeyPair.getPublicKey(), message.getY(), t);
        // Generate response message and transition into next state.
        final AuthRMessage authRMessage = new AuthRMessage(FOUR, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), profilePayload, this.ourECDHKeyPair.getPublicKey(),
                this.ourDHKeyPair.getPublicKey(), sigma);
        context.transition(this, new StateAwaitingAuthI(getAuthState(), this.queryTag, this.ourECDHKeyPair,
                this.ourDHKeyPair, message.getY(), message.getB(), ourProfile, message.getClientProfile()));
        return authRMessage;
    }

    private void handleAuthIMessage(@Nonnull final Context context, @Nonnull final AuthIMessage message)
            throws ValidationException {
        final ClientProfile profileBobValidated = this.profileBob.validate();
        final ClientProfile ourProfileValidated = this.ourProfile.validate();
        validate(message, this.queryTag, this.ourProfile, ourProfileValidated, this.profileBob, profileBobValidated,
                this.ourECDHKeyPair.getPublicKey(), this.y, this.ourDHKeyPair.getPublicKey(), this.b,
                context.getSessionID().getUserID(), context.getSessionID().getAccountID());
        secure(context, new SecurityParameters4(THEIRS, this.ourECDHKeyPair, this.ourDHKeyPair, this.y, this.b,
                ourProfileValidated, profileBobValidated));
    }

    @Nullable
    @Override
    String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv3 data message in state WAITING_AUTH_I. Message cannot be read.");
        handleUnreadableMessage(context, message);
        return null;
    }

    @Nullable
    @Override
    String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv4 data message in state WAITING_AUTH_I. Message cannot be read.");
        handleUnreadableMessage(context, message);
        return null;
    }

    @Override
    public void end(@Nonnull final Context context) {
        this.ourDHKeyPair.close();
        this.ourECDHKeyPair.close();
        context.transition(this, new StatePlaintext(getAuthState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy (i.e. we need to destroy different material for different transitions)
    }
}
