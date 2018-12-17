/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.Message;
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
import java.security.interfaces.DSAPublicKey;
import java.util.List;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthRMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_I;
import static net.java.otr4j.messages.MysteriousT4.encode;
import static net.java.otr4j.session.state.SecurityParameters4.Component.OURS;

/**
 * OTRv4 AKE state AWAITING_AUTH_R.
 */
final class StateAwaitingAuthR extends AbstractCommonState {

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
     * The query tag that triggered this DAKE. The query tag is part of the shared session state common knowledge that
     * is verified.
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

    StateAwaitingAuthR(@Nonnull final AuthState authState, @Nonnull final ECDHKeyPair ecdhKeyPair,
            @Nonnull final DHKeyPair dhKeyPair, @Nonnull final ClientProfilePayload ourProfilePayload,
            @Nonnull final String queryTag, @Nonnull final IdentityMessage previousMessage) {
        super(authState);
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.ourProfilePayload = requireNonNull(ourProfilePayload);
        this.queryTag = requireNonNull(queryTag);
        this.previousMessage = requireNonNull(previousMessage);
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
    public Message transformSending(@Nonnull final Context context, @Nonnull final String msgText,
            @Nonnull final List<TLV> tlvs, final byte flags) {
        // FIXME implement transformSending
        throw new UnsupportedOperationException("To be implemented");
    }

    @Nullable
    @Override
    AbstractEncodedMessage handleAKEMessage(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) {
        if (message instanceof IdentityMessage) {
            try {
                return handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final OtrCryptoException | ValidationException e) {
                LOGGER.log(INFO, "Failed to process Identity message.", e);
                return null;
            }
        }
        if (message instanceof AuthRMessage) {
            try {
                return handleAuthRMessage(context, (AuthRMessage) message);
            } catch (final OtrCryptoException | ValidationException e) {
                LOGGER.log(WARNING, "Failed to process Auth-R message.", e);
                return null;
            }
        }
        // OTR: "Ignore the message."
        LOGGER.log(INFO, "We only expect to receive an Identity message or an Auth-R message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
        return null;
    }

    @Nonnull
    @Override
    AbstractEncodedMessage handleIdentityMessage(@Nonnull final Context context,
            @Nonnull final IdentityMessage message) throws OtrCryptoException, ValidationException {
        final ClientProfile theirProfile = message.getClientProfile().validate();
        IdentityMessages.validate(message, theirProfile);
        if (this.previousMessage.getB().compareTo(message.getB()) > 0) {
            // No state change necessary, we assume that by resending other party will still follow existing protocol
            // execution.
            return this.previousMessage;
        }
        // Clear old key material, then start a new DAKE from scratch with different keys.
        this.dhKeyPair.close();
        this.ecdhKeyPair.close();
        // Pretend we are still in initial state and handle Identity message accordingly.
        return super.handleIdentityMessage(context, message);
    }

    @Nonnull
    private AuthIMessage handleAuthRMessage(@Nonnull final Context context, @Nonnull final AuthRMessage message)
            throws OtrCryptoException, ValidationException {
        final SessionID sessionID = context.getSessionID();
        final EdDSAKeyPair ourLongTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        final ClientProfile ourClientProfile = this.ourProfilePayload.validate();
        final ClientProfile theirClientProfile = message.getClientProfile().validate();
        validate(message, this.ourProfilePayload, ourClientProfile, theirClientProfile, sessionID.getUserID(),
                sessionID.getAccountID(), this.ecdhKeyPair.getPublicKey(), this.dhKeyPair.getPublicKey(), this.queryTag);
        final SecurityParameters4 params = new SecurityParameters4(OURS, ecdhKeyPair, dhKeyPair, message.getX(),
                message.getA(), ourClientProfile, theirClientProfile);
        secure(context, params);
        final InstanceTag senderTag = context.getSenderInstanceTag();
        final InstanceTag receiverTag = context.getReceiverInstanceTag();
        final byte[] t = encode(AUTH_I, message.getClientProfile(), this.ourProfilePayload, message.getX(),
                this.ecdhKeyPair.getPublicKey(), message.getA(), this.dhKeyPair.getPublicKey(), senderTag.getValue(),
                receiverTag.getValue(), this.queryTag, sessionID.getAccountID(), sessionID.getUserID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), ourLongTermKeyPair,
                ourLongTermKeyPair.getPublicKey(), theirClientProfile.getForgingKey(), message.getX(), t);
        return new AuthIMessage(FOUR, senderTag, receiverTag, sigma);
    }

    @Nullable
    @Override
    String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) {
        // FIXME implement handleDataMessage
        throw new UnsupportedOperationException("To be implemented");
    }

    @Nullable
    @Override
    String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message) {
        // FIXME implement handleDataMessage
        throw new UnsupportedOperationException("To be implemented");
    }

    @Override
    public void end(@Nonnull final Context context) {
        this.dhKeyPair.close();
        this.ecdhKeyPair.close();
        context.transition(this, new StatePlaintext(getAuthState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy (i.e. we need to destroy different material for different transitions)
    }
}
