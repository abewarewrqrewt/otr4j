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
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
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
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FIRST_ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthRMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_I;
import static net.java.otr4j.messages.MysteriousT4.encode;
import static net.java.otr4j.session.state.DoubleRatchet.Role.BOB;

/**
 * OTRv4 AKE state AWAITING_AUTH_R.
 */
// TODO check OTRv4 spec for instructions on temporarily storing recently received messages while negotiating.
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

    private final ECDHKeyPair ourFirstECDHKeyPair;

    private final DHKeyPair ourFirstDHKeyPair;

    StateAwaitingAuthR(@Nonnull final AuthState authState, @Nonnull final ECDHKeyPair ecdhKeyPair,
            @Nonnull final DHKeyPair dhKeyPair, @Nonnull final ECDHKeyPair ourFirstECDHKeyPair,
            @Nonnull final DHKeyPair ourFirstDHKeyPair, @Nonnull final ClientProfilePayload ourProfilePayload,
            @Nonnull final IdentityMessage previousMessage) {
        super(authState);
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.ourFirstECDHKeyPair = requireNonNull(ourFirstECDHKeyPair);
        this.ourFirstDHKeyPair = requireNonNull(ourFirstDHKeyPair);
        this.ourProfilePayload = requireNonNull(ourProfilePayload);
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
    AbstractEncodedMessage handleAKEMessage(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) {
        if (message instanceof IdentityMessage) {
            try {
                return handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(INFO, "Failed to process Identity message.", e);
                return null;
            }
        }
        if (message instanceof AuthRMessage) {
            try {
                return handleAuthRMessage(context, (AuthRMessage) message);
            } catch (final ValidationException e) {
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
    AbstractEncodedMessage handleIdentityMessage(@Nonnull final Context context, @Nonnull final IdentityMessage message)
            throws ValidationException {
        final ClientProfile theirProfile = message.clientProfile.validate();
        IdentityMessages.validate(message, theirProfile);
        if (this.previousMessage.b.compareTo(message.b) > 0) {
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
            throws ValidationException {
        final SessionID sessionID = context.getSessionID();
        final EdDSAKeyPair ourLongTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        // Validate received Auth-R message.
        final ClientProfile ourClientProfile = this.ourProfilePayload.validate();
        final ClientProfile theirClientProfile = message.clientProfile.validate();
        validate(message, this.ourProfilePayload, ourClientProfile, theirClientProfile, sessionID.getUserID(),
                sessionID.getAccountID(), this.ecdhKeyPair.getPublicKey(), this.dhKeyPair.getPublicKey(),
                this.ourFirstECDHKeyPair.getPublicKey(), this.ourFirstDHKeyPair.getPublicKey());
        final SecureRandom secureRandom = context.secureRandom();
        // Prepare Auth-I message to be sent.
        final InstanceTag senderTag = context.getSenderInstanceTag();
        final InstanceTag receiverTag = context.getReceiverInstanceTag();
        final byte[] t = encode(AUTH_I, message.clientProfile, this.ourProfilePayload, message.x,
                this.ecdhKeyPair.getPublicKey(), message.a, this.dhKeyPair.getPublicKey(),
                this.ourFirstECDHKeyPair.getPublicKey(), this.ourFirstDHKeyPair.getPublicKey(),
                message.ourFirstECDHPublicKey, message.ourFirstDHPublicKey, senderTag, receiverTag,
                sessionID.getAccountID(), sessionID.getUserID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(secureRandom, ourLongTermKeyPair,
                ourLongTermKeyPair.getPublicKey(), theirClientProfile.getForgingKey(), message.x, t);
        final AuthIMessage reply = new AuthIMessage(FOUR, senderTag, receiverTag, sigma);
        // Calculate mixed shared secret and SSID.
        final byte[] k;
        final byte[] ssid;
        try (SharedSecret4 sharedSecret = new SharedSecret4(secureRandom, this.dhKeyPair, this.ecdhKeyPair, message.a,
                message.x)) {
            k = sharedSecret.getK();
            ssid = sharedSecret.generateSSID();
        }
        // Initialize Double Ratchet.
        final SharedSecret4 firstRatchetSecret = new SharedSecret4(secureRandom, ourFirstDHKeyPair, ourFirstECDHKeyPair,
                message.ourFirstDHPublicKey, message.ourFirstECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(firstRatchetSecret, kdf1(FIRST_ROOT_KEY, k, 64), BOB);
        secure(context, ssid, ratchet, ourClientProfile.getLongTermPublicKey(), theirClientProfile.getLongTermPublicKey());
        return reply;
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
        this.dhKeyPair.close();
        this.ecdhKeyPair.close();
        this.ourFirstDHKeyPair.close();
        this.ourFirstECDHKeyPair.close();
        context.transition(this, new StatePlaintext(getAuthState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy (i.e. we need to destroy different material for different transitions)
    }
}
