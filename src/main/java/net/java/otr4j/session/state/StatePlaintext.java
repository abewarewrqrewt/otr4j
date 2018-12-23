/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Level.INFO;
import static net.java.otr4j.api.OtrEngineHostUtil.requireEncryptedMessage;
import static net.java.otr4j.api.OtrPolicyUtil.allowedVersions;

/**
 * Message state PLAINTEXT. This is the only message state that is publicly
 * accessible. Message states and transitions are always initiated from the
 * initial state.
 *
 * @author Danny van Heumen
 */
// FIXME write additional unit tests for StatePlaintext
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
        } catch (final ValidationException e) {
            LOGGER.log(INFO, "Failed to process Identity message.", e);
            return null;
        }
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
            @Nonnull final Iterable<TLV> tlvs, final byte flags) throws OtrException {
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

    @Override
    public void destroy() {
        // no sensitive material to destroy
    }
}
