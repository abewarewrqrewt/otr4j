/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static net.java.otr4j.api.OtrEngineHostUtil.getReplyForUnreadableMessage;
import static net.java.otr4j.api.OtrEngineHostUtil.requireEncryptedMessage;
import static net.java.otr4j.api.OtrEngineHostUtil.unencryptedMessageReceived;
import static net.java.otr4j.api.OtrEngineHostUtil.unreadableMessageReceived;
import static net.java.otr4j.api.OtrPolicyUtil.allowedVersions;

/**
 * Message state PLAINTEXT. This is the only message state that is publicly
 * accessible. Message states and transitions are always initiated from the
 * initial state.
 *
 * @author Danny van Heumen
 */
public final class StatePlaintext extends AbstractState {

    private final SessionID sessionId;

    /**
     * Constructor for the Plaintext message state.
     *
     * @param sessionId the session ID
     */
    public StatePlaintext(final SessionID sessionId) {
        super();
        this.sessionId = Objects.requireNonNull(sessionId);
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    @Nonnull
    public SessionID getSessionID() {
        return this.sessionId;
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
    public PublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available in plaintext state.");
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available in plaintext state.");
    }

    @Override
    @Nullable
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage message) throws OtrException {
        final OtrEngineHost host = context.getHost();
        unreadableMessageReceived(host, sessionId);
        final String replymsg = getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
        context.injectMessage(new ErrorMessage(replymsg));
        return null;
    }

    @Nullable
    @Override
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message) throws OtrException {
        final OtrEngineHost host = context.getHost();
        unreadableMessageReceived(host, sessionId);
        final String replymsg = getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
        context.injectMessage(new ErrorMessage(replymsg));
        return null;
    }

    @Override
    @Nonnull
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) {
        // Simply display the message to the user. If REQUIRE_ENCRYPTION is set,
        // warn him that the message was received unencrypted.
        if (context.getSessionPolicy().isRequireEncryption()) {
            unencryptedMessageReceived(context.getHost(), this.sessionId, plainTextMessage.getCleanText());
        }
        return plainTextMessage.getCleanText();
    }

    @Override
    @Nullable
    public Message transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) throws OtrException {
        final OtrPolicy otrPolicy = context.getSessionPolicy();
        if (otrPolicy.isRequireEncryption()) {
            // Prevent original message from being sent. Start AKE.
            if (!otrPolicy.viable()) {
                throw new OtrException("OTR policy disallows all versions of the OTR protocol. We cannot initiate a new OTR session.");
            }
            context.startSession();
            requireEncryptedMessage(context.getHost(), sessionId, msgText);
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
