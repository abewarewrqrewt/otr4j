/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.OtrEngineHostUtil.requireEncryptedMessage;
import static net.java.otr4j.api.OtrPolicyUtil.allowedVersions;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.IdentityMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;

/**
 * Message state PLAINTEXT. This is the only message state that is publicly
 * accessible. Message states and transitions are always initiated from the
 * initial state.
 *
 * @author Danny van Heumen
 */
// FIXME write additional unit tests for StatePlaintext
// FIXME clean up method implementations now that we base on AbstractCommonState.
public final class StatePlaintext extends AbstractCommonState {

    private static final Logger LOGGER = Logger.getLogger(StatePlaintext.class.getName());

    /**
     * Constructor for the Plaintext message state.
     *
     * @param authState the initial authentication (AKE) state instance.
     */
    public StatePlaintext(@Nonnull final AuthState authState) {
        super(authState);
    }

    @Nonnull
    @Override
    public AbstractEncodedMessage initiateAKE(@Nonnull final Context context, final int version,
            @Nonnull final InstanceTag receiverInstanceTag, @Nonnull final String queryTag) {
        return super.initiateAKE(context, version, receiverInstanceTag, queryTag);
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return SessionStatus.PLAINTEXT;
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available in plaintext state.");
    }

    @Override
    @Nonnull
    public DSAPublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available in plaintext state.");
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available in plaintext state.");
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy
    }

    @Nullable
    @Override
    AbstractEncodedMessage handleAKEMessage(@Nonnull final Context context, @Nonnull final AbstractEncodedMessage message) {
        if (!context.getSessionPolicy().isAllowV4()) {
            LOGGER.finest("ALLOW_V4 is not set, ignore this message.");
            return null;
        }
        if (!(message instanceof IdentityMessage)) {
            LOGGER.log(Level.FINE, "Ignoring unexpected DAKE message type: " + message.getType());
            return null;
        }
        try {
            return handleIdentityMessage(context, (IdentityMessage) message);
        } catch (final OtrCryptoException | ValidationException e) {
            // FIXME consider how to handle this case and where.
            LOGGER.log(WARNING, "Failed to process Identity message.", e);
            return null;
        }
    }

    // FIXME evaluate whether we need to lift this to AbstractOTR4State ... may be needed in case user is in StateEncrypted3/4 and still be able to handle new DAKE process.
    // FIXME verify that message is correctly rejected + nothing responded when verification of IdentityMessage fails.
    @Nonnull
    private AuthRMessage handleIdentityMessage(@Nonnull final Context context, @Nonnull final IdentityMessage message)
            throws OtrCryptoException, ValidationException {
        final ClientProfile theirClientProfile = message.getClientProfile().validate();
        validate(message, theirClientProfile);
        final ClientProfilePayload profile = context.getClientProfilePayload();
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair x = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair a = DHKeyPair.generate(secureRandom);
        final SessionID sessionID = context.getSessionID();
        final EdDSAKeyPair longTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        // TODO should we verify that long-term key pair matches with long-term public key from user profile? (This would be an internal sanity check.)
        // Generate t value and calculate sigma based on known facts and generated t value.
        final String queryTag = context.getQueryTag();
        final byte[] t = encode(AUTH_R, profile, message.getClientProfile(), x.getPublicKey(), message.getY(),
                a.getPublicKey(), message.getB(), context.getSenderInstanceTag().getValue(),
                context.getReceiverInstanceTag().getValue(), queryTag, sessionID.getAccountID(),
                sessionID.getUserID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(secureRandom, longTermKeyPair,
                theirClientProfile.getForgingKey(), longTermKeyPair.getPublicKey(), message.getY(), t);
        // Generate response message and transition into next state.
        final AuthRMessage authRMessage = new AuthRMessage(FOUR, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), profile, x.getPublicKey(), a.getPublicKey(), sigma);
        context.transition(this, new StateAwaitingAuthI(getAuthState(), queryTag, x, a, message.getY(), message.getB(),
                profile, message.getClientProfile()));
        return authRMessage;
    }

    @Override
    @Nullable
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message)
            throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv3 data message in PLAINTEXT state. Message cannot be read.");
        handleUnreadableMessage(context, message);
        return null;
    }

    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message)
            throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv4 data message in PLAINTEXT state. Message cannot be read.");
        handleUnreadableMessage(context, message);
        return null;
    }

    @Override
    @Nullable
    public Message transformSending(@Nonnull final Context context, @Nonnull final String msgText,
            @Nonnull final List<TLV> tlvs, final byte flags) throws OtrException {
        final OtrPolicy otrPolicy = context.getSessionPolicy();
        if (otrPolicy.isRequireEncryption()) {
            // Prevent original message from being sent. Start AKE.
            if (!otrPolicy.viable()) {
                throw new OtrException("OTR policy disallows all versions of the OTR protocol. We cannot initiate a new OTR session.");
            }
            context.startSession();
            requireEncryptedMessage(context.getHost(), context.getSessionID(), msgText);
            return null;
        }
        if (!otrPolicy.isSendWhitespaceTag() || context.getOfferStatus() == OfferStatus.REJECTED) {
            // As we do not want to send a specially crafted whitespace tag
            // message, just return the original message text to be sent.
            return new PlainTextMessage(Collections.<Integer>emptySet(), msgText);
        }
        // Continue with crafting a special whitespace message tag and embedding it into the original message.
        final Set<Integer> versions = allowedVersions(otrPolicy);
        if (versions.isEmpty()) {
            // Catch situation where we do not actually offer any versions.
            // At this point, reaching this state is considered a bug.
            throw new IllegalStateException("The current OTR policy does not allow any supported version of OTR. The software should either enable some protocol version or disable sending whitespace tags.");
        }
        final PlainTextMessage m = new PlainTextMessage(versions, msgText);
        context.setOfferStatusSent();
        return m;
    }

    @Override
    public void end(@Nonnull final Context context) {
        // already in "ended" state
    }
}
