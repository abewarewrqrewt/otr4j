/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.DHKeyMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.session.ake.AuthContext;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.SecurityParameters;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.OtrEngineHostUtil.showError;
import static net.java.otr4j.api.Session.Version.THREE;
import static net.java.otr4j.api.Session.Version.TWO;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.messages.EncodedMessageParser.parseEncodedMessage;
import static net.java.otr4j.session.state.Contexts.signalUnreadableMessage;

/**
 * Abstract base implementation for session state implementations.
 * <p>
 * This abstract base implementation focuses on providing a general mechanism for handling authentication (AKE) message
 * and state handling. Anything that is not AKE-related will be deferred to the state implementation subclass.
 *
 * @author Danny van Heumen
 */
abstract class AbstractOTR3State implements State, AuthContext {

    // TODO is this "anonymous" logging an issue? (I.e. no session information in the log message.)
    private static final Logger LOGGER = Logger.getLogger(AbstractOTR3State.class.getName());

    final Context context;

    /**
     * State management for the AKE negotiation.
     */
    @Nonnull
    private volatile AuthState authState;

    AbstractOTR3State(@Nonnull final Context context, @Nonnull final AuthState authState) {
        this.context = requireNonNull(context);
        this.authState = requireNonNull(authState);
    }

    @Nonnull
    @Override
    public SecureRandom secureRandom() {
        return this.context.secureRandom();
    }

    @Nonnull
    @Override
    public InstanceTag getSenderTag() {
        return this.context.getSenderInstanceTag();
    }

    @Nonnull
    @Override
    public InstanceTag getReceiverTag() {
        return this.context.getReceiverInstanceTag();
    }

    @Nonnull
    @Override
    public DSAKeyPair getLocalKeyPair() {
        return context.getHost().getLocalKeyPair(context.getSessionID());
    }

    @Nonnull
    @Override
    public SessionID getSessionID() {
        return this.context.getSessionID();
    }

    @Nonnull
    @Override
    public AuthState getAuthState() {
        return this.authState;
    }

    @Override
    public void setAuthState(@Nonnull final AuthState state) {
        LOGGER.fine("Transitioning authentication state to " + state);
        this.authState = requireNonNull(state);
    }

    @Override
    public void handleErrorMessage(@Nonnull final ErrorMessage errorMessage) throws OtrException {
        showError(context.getHost(), this.getSessionID(), errorMessage.error);
    }

    void handleUnreadableMessage(@Nonnull final DataMessage message) throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context);
    }

    void handleUnreadableMessage(@Nonnull final DataMessage4 message) throws OtrException {
        if ((message.getFlags() & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context);
    }

    @Override
    public void secure(@Nonnull final SecurityParameters params) throws InteractionFailedException {
        try {
            this.context.transition(this, new StateEncrypted3(this.context, this.authState, params));
        } catch (final OtrCryptoException e) {
            throw new InteractionFailedException(e);
        }
        if (this.context.getSessionStatus() != ENCRYPTED) {
            throw new IllegalStateException("Session failed to transition to ENCRYPTED. (OTRv2/OTRv3)");
        }
        LOGGER.info("Session secured. Message state transitioned to ENCRYPTED. (OTRv2/OTRv3)");
        if (context.getMasterSession().getOutgoingSession().getSessionStatus() == PLAINTEXT) {
            // This behavior is adopted to preserve behavior between otr4j before refactoring and after. Originally,
            // the master session would contain some fields that would indicate session status even though a slave
            // session was created. Now we ensure that once we have secured the session, we also switch to that
            // session such that subsequently sent messages are already encrypted, even if the client does not
            // explicitly switch.
            LOGGER.finest("Switching to the just-secured session, as the previous state was a PLAINTEXT state.");
            context.getMasterSession().setOutgoingSession(context.getReceiverInstanceTag());
        }
    }

    @Nullable
    @Override
    public String handleEncodedMessage(@Nonnull final EncodedMessage message) throws OtrException {
        // In case of OTRv3 delegate message processing to dedicated slave session.
        final AbstractEncodedMessage encodedM;
        try {
            encodedM = parseEncodedMessage(message.getVersion(), message.getType(), message.getSenderInstanceTag(),
                    message.getReceiverInstanceTag(), message.getPayload());
        } catch (final ProtocolException e) {
            // TODO we probably want to just drop the message, i.s.o. throwing exception.
            throw new OtrException("Invalid encoded message content.", e);
        }

        // FIXME can we separate out the OTRv4 message type and distribute over the various abstract base classes
        assert !ZERO_TAG.equals(encodedM.receiverInstanceTag) || encodedM instanceof DHCommitMessage
                || encodedM instanceof IdentityMessage || encodedM instanceof AuthRMessage
                : "BUG: receiver instance should be set for anything other than the first AKE message.";

        // FIXME need to do anything still, now that transitioning to slave session happens before calling this method (e.g. state management in case of DH-Key message)
        // TODO We've started replicating current authState in *all* cases where a new slave session is created. Is this indeed correct? Probably is, but needs focused verification.
        try {
            final SessionID sessionID = context.getSessionID();
            if (encodedM instanceof DataMessage) {
                LOGGER.log(Level.FINEST, "{0} received a data message (OTRv2/OTRv3) from {1}, handling in state {2}.",
                        new Object[]{sessionID.getAccountID(), sessionID.getUserID(), this.getClass().getName()});
                return handleDataMessage((DataMessage) encodedM);
            }
            // FIXME see if we can lift DataMessage4 handling into the AbstractOTR4State.
            if (encodedM instanceof DataMessage4) {
                LOGGER.log(Level.FINEST, "{0} received a data message (OTRv4) from {1}, handling in state {2}.",
                        new Object[]{sessionID.getAccountID(), sessionID.getUserID(), this.getClass().getName()});
                return handleDataMessage((DataMessage4) encodedM);
            }
            // Anything that is not a Data message is some type of AKE message.
            final AbstractEncodedMessage reply = handleAKEMessage(encodedM);
            if (reply != null) {
                context.injectMessage(reply);
            }
        } catch (final ProtocolException e) {
            LOGGER.log(Level.FINE, "An illegal message was received. Processing was aborted.", e);
            // TODO consider how we should signal unreadable message for illegal data messages and potentially show error to client. (Where we escape handling logic through ProtocolException.)
        }
        return null;
    }

    @Nullable
    AbstractEncodedMessage handleAKEMessage(@Nonnull final AbstractEncodedMessage m) {
        final SessionID sessionID = context.getSessionID();
        LOGGER.log(Level.FINEST, "{0} received an AKE message from {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        // Verify that policy allows handling message according to protocol version.
        final OtrPolicy policy = context.getSessionPolicy();
        if (m.protocolVersion == TWO && !policy.isAllowV2()) {
            LOGGER.finest("ALLOW_V2 is not set, ignore this message.");
            return null;
        }
        if (m.protocolVersion == THREE && !policy.isAllowV3()) {
            LOGGER.finest("ALLOW_V3 is not set, ignore this message.");
            return null;
        }

        // Verify that we received an AKE message using the previously agreed upon protocol version. Exception to this
        // rule for DH Commit message, as this message initiates a new AKE negotiation and thus proposes a new protocol
        // version corresponding to the message's intention.
        if (!(m instanceof DHCommitMessage) && !(m instanceof DHKeyMessage) && m.protocolVersion != this.authState.getVersion()) {
            LOGGER.log(Level.INFO, "AKE message containing unexpected protocol version encountered. ({0} instead of {1}.) Ignoring.",
                    new Object[]{m.protocolVersion, this.authState.getVersion()});
            return null;
        }

        LOGGER.log(Level.FINEST, "Handling AKE message in state {0}", this.authState.getClass().getName());
        try {
            return this.authState.handle(this, m);
        } catch (final ProtocolException e) {
            LOGGER.log(Level.FINEST, "Ignoring message. Bad message content / incomplete message received.", e);
            return null;
        } catch (final OtrCryptoException e) {
            LOGGER.log(Level.FINEST, "Ignoring message. Exception while processing message due to cryptographic verification failure.", e);
            return null;
        } catch (final AuthContext.InteractionFailedException e) {
            LOGGER.log(Level.WARNING, "Failed to transition to ENCRYPTED message state.", e);
            return null;
        } catch (final OtrException e) {
            LOGGER.log(Level.FINEST, "Ignoring message. Exception while processing message due to non-cryptographic error.", e);
            return null;
        }
    }

    @Nonnull
    @Override
    public AbstractEncodedMessage initiateAKE(final int version, final InstanceTag receiverInstanceTag, final String queryTag) {
        return this.authState.initiate(this, version, receiverInstanceTag, queryTag);
    }

    /**
     * Handle the received data message in OTRv2/OTRv3 format.
     *
     * @param message The received data message.
     * @return Returns the decrypted message text.
     * @throws ProtocolException In case of I/O reading fails.
     * @throws OtrException      In case an exception occurs.
     */
    @Nullable
    abstract String handleDataMessage(@Nonnull DataMessage message) throws ProtocolException, OtrException;

    /**
     * Handle the received data message in OTRv4 format.
     *
     * @param message The received data message.
     * @return Returns the decrypted message text.
     * @throws ProtocolException In case of I/O reading failures.
     * @throws OtrException      In case of failures regarding the OTR protocol (implementation).
     */
    @Nullable
    abstract String handleDataMessage(@Nonnull DataMessage4 message) throws ProtocolException, OtrException;
}
