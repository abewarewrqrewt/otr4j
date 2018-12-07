/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;

abstract class AbstractOTR4State extends AbstractOTR3State {

    private static final Logger LOGGER = Logger.getLogger(AbstractOTR4State.class.getName());

    AbstractOTR4State(@Nonnull final Context context, @Nonnull final AuthState authState) {
        super(context, authState);
    }

    @Nonnull
    @Override
    public AbstractEncodedMessage initiateAKE(final int version, @Nonnull final InstanceTag receiverInstanceTag,
            @Nonnull final String queryTag) {
        if (version != FOUR) {
            return super.initiateAKE(version, receiverInstanceTag, queryTag);
        }
        final ECDHKeyPair ourECDHkeyPair = ECDHKeyPair.generate(context.secureRandom());
        final DHKeyPair ourDHkeyPair = DHKeyPair.generate(context.secureRandom());
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final IdentityMessage message = new IdentityMessage(FOUR, context.getSenderInstanceTag(),
                receiverInstanceTag, profilePayload, ourECDHkeyPair.getPublicKey(), ourDHkeyPair.getPublicKey());
        context.transition(this, new StateAwaitingAuthR(context, getAuthState(), ourECDHkeyPair, ourDHkeyPair,
                profilePayload, queryTag, message));
        return message;
    }

    void secure(@Nonnull final SecurityParameters4 params) {
        try {
            final StateEncrypted4 encrypted = new StateEncrypted4(this.context, params, getAuthState());
            this.context.transition(this, encrypted);
            if (params.getInitializationComponent() == SecurityParameters4.Component.THEIRS) {
                LOGGER.log(Level.FINE, "We initialized THEIR component of the Double Ratchet, so it is complete. Sending heartbeat message.");
                this.context.injectMessage(encrypted.transformSending("", Collections.<TLV>emptyList(),
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
        if (this.context.getSessionStatus() != ENCRYPTED) {
            throw new IllegalStateException("Session failed to transition to ENCRYPTED (OTRv4).");
        }
        LOGGER.info("Session secured. Message state transitioned to ENCRYPTED. (OTRv4)");
        if (context.getMasterSession().getOutgoingSession().getSessionStatus() == PLAINTEXT) {
            LOGGER.finest("Switching to the just-secured session, as the previous outgoing session was a PLAINTEXT state.");
            context.getMasterSession().setOutgoingSession(context.getReceiverInstanceTag());
        }
    }
}
