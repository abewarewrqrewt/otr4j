package net.java.otr4j.session.ake;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthIMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.IdentityMessages;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.api.ClientProfile;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthIMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;

/**
 * The state AWAITING_AUTH_I.
 *
 * This is a state in which Alice will be while awaiting Bob's final message.
 */
// FIXME migrate into Message State state machine.
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

    StateAwaitingAuthI(@Nonnull final String queryTag, @Nonnull final ECDHKeyPair ourECDHKeyPair,
            @Nonnull final DHKeyPair ourDHKeyPair, @Nonnull final Point y, @Nonnull final BigInteger b,
            @Nonnull final ClientProfilePayload ourProfile, @Nonnull final ClientProfilePayload profileBob) {
        super();
        this.queryTag = requireNonNull(queryTag);
        this.ourECDHKeyPair = requireNonNull(ourECDHKeyPair);
        this.ourDHKeyPair = requireNonNull(ourDHKeyPair);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.ourProfile = requireNonNull(ourProfile);
        this.profileBob = requireNonNull(profileBob);
    }

    @Nullable
    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message)
            throws OtrCryptoException, ValidationException {
        // FIXME need to verify protocol versions?
        if (message instanceof IdentityMessage) {
            return handleIdentityMessage(context, (IdentityMessage) message);
        }
        if (message instanceof AuthIMessage) {
            handleAuthIMessage(context, (AuthIMessage) message);
            // FIXME need to send heartbeat message or queued user message in order to finalize Double Ratchet for other party.
            return null;
        }
        // OTR: "Ignore the message."
        LOGGER.log(Level.INFO, "We only expect to receive an Identity message or an Auth-I message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
        return null;
    }

    /**
     * Handle Identity message.
     * <p>
     * This implementation deviates from the implementation in StateInitial as we reuse previously generated variables.
     *
     * @param context the authentication context
     * @param message the identity message
     * @return Returns the Auth-R message to send
     * @throws OtrCryptoException  In case of failure to validate cryptographic components in other party's identity
     *                             message.
     * @throws ValidationException In case of failure to validate other party's identity message or client profile.
     */
    private AuthRMessage handleIdentityMessage(@Nonnull final AuthContext context, @Nonnull final IdentityMessage message)
            throws OtrCryptoException, ValidationException {
        IdentityMessages.validate(message);
        final ClientProfile theirNewClientProfile = message.getClientProfile().validate();
        // Note: we query the context for a new client profile, because we're responding to a new Identity message.
        // This ensures a "fresh" profile. (May be unnecessary, but seems smart right now ... I may regret it later)
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final EdDSAKeyPair longTermKeyPair = context.getLongTermKeyPair();
        // TODO should we verify that long-term key pair matches with long-term public key from user profile? (This would be an internal sanity check.)
        // Generate t value and calculate sigma based on known facts and generated t value.
        final byte[] t = encode(AUTH_R, profilePayload, message.getClientProfile(), this.ourECDHKeyPair.getPublicKey(),
            message.getY(), this.ourDHKeyPair.getPublicKey(), message.getB(), context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue(), this.queryTag, context.getRemoteAccountID(),
            context.getLocalAccountID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), longTermKeyPair,
                theirNewClientProfile.getLongTermPublicKey(), longTermKeyPair.getPublicKey(), message.getY(), t);
        // Generate response message and transition into next state.
        final AuthRMessage authRMessage = new AuthRMessage(Session.OTRv.FOUR, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), profilePayload, this.ourECDHKeyPair.getPublicKey(),
                this.ourDHKeyPair.getPublicKey(), sigma);
        context.setState(new StateAwaitingAuthI(this.queryTag, this.ourECDHKeyPair, this.ourDHKeyPair, message.getY(),
                message.getB(), ourProfile, message.getClientProfile()));
        return authRMessage;
    }

    private void handleAuthIMessage(@Nonnull final AuthContext context, @Nonnull final AuthIMessage message)
            throws OtrCryptoException, ValidationException {
        try {
            validate(message, this.queryTag, this.ourProfile, this.profileBob, this.ourECDHKeyPair.getPublicKey(),
                    this.y, this.ourDHKeyPair.getPublicKey(), this.b, context.getRemoteAccountID(),
                    context.getLocalAccountID());
            // FIXME check if we can pass in a previously validated profileBob instance.
            final SecurityParameters4 params = new SecurityParameters4(SecurityParameters4.Component.THEIRS,
                    this.ourECDHKeyPair, this.ourDHKeyPair, this.y, this.b, this.ourProfile.validate(),
                    this.profileBob.validate());
            context.secure(params);
        } finally {
            context.setState(StateInitial.empty());
        }
    }

    @Override
    public int getVersion() {
        return Session.OTRv.FOUR;
    }
}
