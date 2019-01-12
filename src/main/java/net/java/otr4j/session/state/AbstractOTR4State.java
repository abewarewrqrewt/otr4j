/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.EncodedMessageParser.parseEncodedMessage;
import static net.java.otr4j.messages.IdentityMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;

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

    /**
     * Method for handling OTRv4 DAKE messages.
     *
     * @param context the session context
     * @param message the AKE message
     * @return Returns the reply for the provided AKE message.
     */
    @Nullable
    abstract AbstractEncodedMessage handleAKEMessage(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message);

    /**
     * Common implementation for handling OTRv4 Identity message that is shared among states.
     *
     * @param context the session context
     * @param message the Identity message to be processed
     * @return Returns reply to Identity message.
     * @throws ValidationException In case of failing to validate received Identity message.
     */
    @Nonnull
    AbstractEncodedMessage handleIdentityMessage(@Nonnull final Context context, @Nonnull final IdentityMessage message)
            throws ValidationException {
        final ClientProfile theirClientProfile = message.clientProfile.validate();
        validate(message, theirClientProfile);
        final ClientProfilePayload profile = context.getClientProfilePayload();
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair x = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair a = DHKeyPair.generate(secureRandom);
        final ECDHKeyPair ourFirstECDHKeyPair = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair ourFirstDHKeyPair = DHKeyPair.generate(secureRandom);
        final SessionID sessionID = context.getSessionID();
        final EdDSAKeyPair longTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        final byte[] k;
        final byte[] ssid;
        try (SharedSecret4 sharedSecret = new SharedSecret4(secureRandom, a, x, message.b, message.y)) {
            k = sharedSecret.getK();
            ssid = sharedSecret.generateSSID();
        }
        // TODO should we verify that long-term key pair matches with long-term public key from user profile? (This would be an internal sanity check.)
        // Generate t value and calculate sigma based on known facts and generated t value.
        final String queryTag = context.getQueryTag();
        final byte[] t = encode(AUTH_R, profile, message.clientProfile, x.getPublicKey(), message.y, a.getPublicKey(),
                message.b, ourFirstECDHKeyPair.getPublicKey(), ourFirstDHKeyPair.getPublicKey(),
                message.ourFirstECDHPublicKey, message.ourFirstDHPublicKey, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), queryTag, sessionID.getAccountID(), sessionID.getUserID());
        final Sigma sigma = ringSign(secureRandom, longTermKeyPair, theirClientProfile.getForgingKey(),
                longTermKeyPair.getPublicKey(), message.y, t);
        // Generate response message and transition into next state.
        final AuthRMessage authRMessage = new AuthRMessage(FOUR, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), profile, x.getPublicKey(), a.getPublicKey(), sigma,
                ourFirstECDHKeyPair.getPublicKey(), ourFirstDHKeyPair.getPublicKey());
        context.transition(this, new StateAwaitingAuthI(getAuthState(), queryTag, k, ssid, x, a,
                ourFirstECDHKeyPair, ourFirstDHKeyPair, message.ourFirstECDHPublicKey, message.ourFirstDHPublicKey,
                message.y, message.b, profile, message.clientProfile));
        return authRMessage;
    }

    @Nonnull
    @Override
    public AbstractEncodedMessage initiateAKE(@Nonnull final Context context, final int version,
            @Nonnull final InstanceTag receiverInstanceTag, @Nonnull final String queryTag) {
        if (version != FOUR) {
            return super.initiateAKE(context, version, receiverInstanceTag, queryTag);
        }
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair ourECDHkeyPair = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair ourDHkeyPair = DHKeyPair.generate(secureRandom);
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final ECDHKeyPair ourFirstECDHKeyPair = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair ourFirstDHKeyPair = DHKeyPair.generate(secureRandom);
        final IdentityMessage message = new IdentityMessage(FOUR, context.getSenderInstanceTag(),
                receiverInstanceTag, profilePayload, ourECDHkeyPair.getPublicKey(), ourDHkeyPair.getPublicKey(),
                ourFirstECDHKeyPair.getPublicKey(), ourFirstDHKeyPair.getPublicKey());
        context.transition(this, new StateAwaitingAuthR(getAuthState(), ourECDHkeyPair, ourDHkeyPair,
                ourFirstECDHKeyPair, ourFirstDHKeyPair, profilePayload, queryTag, message));
        return message;
    }

    /**
     * Secure existing session, i.e. transition to `ENCRYPTED_MESSAGES`. This ensures that, apart from transitioning to
     * the encrypted messages state, that we also set the default outgoing session to this instance, if the current
     * outgoing session is not secured yet.
     *
     * @param context                the session context
     * @param ssid                   the session's SSID
     * @param ratchet                the initialized double ratchet
     * @param ourLongTermPublicKey   our long-term public key as used in the DAKE
     * @param theirLongTermPublicKey their long-term public key as used in the DAKE
     */
    final void secure(@Nonnull final Context context, @Nonnull final byte[] ssid, @Nonnull final DoubleRatchet ratchet,
            @Nonnull final Point ourLongTermPublicKey, @Nonnull final Point theirLongTermPublicKey) {
        final StateEncrypted4 encrypted = new StateEncrypted4(context, ssid, ourLongTermPublicKey,
                theirLongTermPublicKey, ratchet, getAuthState());
        context.transition(this, encrypted);
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
