/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.messages.EncodedMessageParser.parseEncodedMessage;

abstract class AbstractOTR4State extends AbstractOTR3State {

    private static final Logger LOGGER = Logger.getLogger(AbstractOTR4State.class.getName());

    AbstractOTR4State(@Nonnull final AuthState authState) {
        super(authState);
    }

    @Nullable
    @Override
    public String handleEncodedMessage(@Nonnull final Context context, @Nonnull final EncodedMessage message) throws OtrException {
        if (message.getVersion() != FOUR) {
            // FIXME is it going to be an issue if we always delegate on message != OTRv4, even if DAKE in progress/finished?
            return super.handleEncodedMessage(context, message);
        }
        final AbstractEncodedMessage encodedM;
        try {
            encodedM = parseEncodedMessage(message.getVersion(), message.getType(), message.getSenderInstanceTag(),
                    message.getReceiverInstanceTag(), message.getPayload());
        } catch (final ProtocolException e) {
            // TODO we probably want to just drop the message, i.s.o. throwing exception.
            throw new OtrException("Invalid encoded message content.", e);
        }
        assert !ZERO_TAG.equals(encodedM.receiverInstanceTag) || encodedM instanceof IdentityMessage
                : "BUG: receiver instance should be set for anything other than the first AKE message.";
        try {
            final SessionID sessionID = context.getSessionID();
            if (encodedM instanceof DataMessage4) {
                LOGGER.log(Level.FINEST, "{0} received a data message (OTRv4) from {1}, handling in state {2}.",
                        new Object[]{sessionID.getAccountID(), sessionID.getUserID(), this.getClass().getName()});
                return handleDataMessage(context, (DataMessage4) encodedM);
            }
            // Anything that is not a Data message is some type of AKE message.
            final AbstractEncodedMessage reply = handleAKEMessage(context, encodedM);
            if (reply != null) {
                context.injectMessage(reply);
            }
        } catch (final ProtocolException e) {
            LOGGER.log(Level.FINE, "An illegal message was received. Processing was aborted.", e);
            // TODO consider how we should signal unreadable message for illegal data messages and potentially show error to client. (Where we escape handling logic through ProtocolException.)
        }
        return null;
    }

    @Nonnull
    @Override
    public AbstractEncodedMessage initiateAKE(@Nonnull final Context context, final int version,
            @Nonnull final InstanceTag receiverInstanceTag, @Nonnull final String queryTag) {
        if (version != FOUR) {
            return super.initiateAKE(context, version, receiverInstanceTag, queryTag);
        }
        final ECDHKeyPair ourECDHkeyPair = ECDHKeyPair.generate(context.secureRandom());
        final DHKeyPair ourDHkeyPair = DHKeyPair.generate(context.secureRandom());
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final IdentityMessage message = new IdentityMessage(FOUR, context.getSenderInstanceTag(),
                receiverInstanceTag, profilePayload, ourECDHkeyPair.getPublicKey(), ourDHkeyPair.getPublicKey());
        context.transition(this, new StateAwaitingAuthR(getAuthState(), ourECDHkeyPair, ourDHkeyPair, profilePayload,
                queryTag, message));
        return message;
    }

    void secure(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) {
        try {
            final StateEncrypted4 encrypted = new StateEncrypted4(context, params, getAuthState());
            context.transition(this, encrypted);
            if (params.getInitializationComponent() == SecurityParameters4.Component.THEIRS) {
                LOGGER.log(Level.FINE, "We initialized THEIR component of the Double Ratchet, so it is complete. Sending heartbeat message.");
                context.injectMessage(encrypted.transformSending(context, "", Collections.<TLV>emptyList(),
                        FLAG_IGNORE_UNREADABLE));
            } else {
                LOGGER.log(Level.FINE, "We initialized OUR component of the Double Ratchet. We are still missing the other party's public key material, hence we cannot send messages yet. Now we wait to receive a message from the other party.");
            }
        } catch (final OtrException e) {
            // We failed to transmit the heartbeat message. This is not critical, although it is annoying for the other
            // party as they will have to wait for the first (user) message from us to complete the Double Ratchet.
            // Without it, they do not have access to the Message Keys that they need to send encrypted messages. (For
            // now, just log the incident and assume things will be alright.)
            LOGGER.log(Level.WARNING, "Failed to send heartbeat message. We need to send a message before the other party can complete their Double Ratchet initialization.",
                    e);
        }
        if (context.getSessionStatus() != ENCRYPTED) {
            throw new IllegalStateException("Session failed to transition to ENCRYPTED (OTRv4).");
        }
        LOGGER.info("Session secured. Message state transitioned to ENCRYPTED. (OTRv4)");
        if (context.getMasterSession().getOutgoingSession().getSessionStatus() == PLAINTEXT) {
            LOGGER.finest("Switching to the just-secured session, as the previous outgoing session was a PLAINTEXT state.");
            context.getMasterSession().setOutgoingSession(context.getReceiverInstanceTag());
        }
    }

    /**
     * Handle the received data message in OTRv4 format.
     *
     * @param message The received data message.
     * @return Returns the decrypted message text.
     * @throws ProtocolException In case of I/O reading failures.
     * @throws OtrException      In case of failures regarding the OTR protocol (implementation).
     */
    @Nullable
    abstract String handleDataMessage(@Nonnull final Context context, @Nonnull DataMessage4 message)
            throws ProtocolException, OtrException;
}
