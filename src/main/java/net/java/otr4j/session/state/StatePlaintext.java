/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineHostUtil;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.OtrPolicyUtil;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.Message;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.ake.SecurityParameters4;

/**
 * Message state PLAINTEXT. This is the only message state that is publicly
 * accessible. Message states and transitions are always initiated from the
 * initial state.
 *
 * @author Danny van Heumen
 */
public final class StatePlaintext extends AbstractState {

    private final SessionID sessionId;

    public StatePlaintext(final SessionID sessionId) {
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
    public SmpTlvHandler getSmpTlvHandler() throws IncorrectStateException {
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
        OtrEngineHostUtil.unreadableMessageReceived(host, sessionId);
        final String replymsg = OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
        context.injectMessage(new ErrorMessage(replymsg));
        return null;
    }

    @Override
    @Nonnull
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) {
        // Simply display the message to the user. If REQUIRE_ENCRYPTION is set,
        // warn him that the message was received unencrypted.
        if (context.getSessionPolicy().getRequireEncryption()) {
            OtrEngineHostUtil.unencryptedMessageReceived(context.getHost(),
                    this.sessionId, plainTextMessage.cleanText);
        }
        return plainTextMessage.cleanText;
    }

    @Override
    @Nullable
    public Message transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) throws OtrException {
        final OtrPolicy otrPolicy = context.getSessionPolicy();
        if (otrPolicy.getRequireEncryption()) {
            // Prevent original message from being sent. Start AKE.
            if (!otrPolicy.viable()) {
                throw new OtrException("OTR policy disallows all versions of the OTR protocol. We cannot initiate a new OTR session.");
            }
            context.startSession();
            OtrEngineHostUtil.requireEncryptedMessage(context.getHost(), sessionId, msgText);
            return null;
        }
        if (!otrPolicy.getSendWhitespaceTag()
                || context.getOfferStatus() == OfferStatus.rejected) {
            // As we do not want to send a specially crafted whitespace tag
            // message, just return the original message text to be sent.
            return new PlainTextMessage(Collections.<Integer>emptySet(), msgText);
        }
        // Continue with crafting a special whitespace message tag and embedding
        // it into the original message.
        final Set<Integer> versions = OtrPolicyUtil.allowedVersions(otrPolicy);
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
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters params) throws OtrException {
        context.setState(new StateEncrypted(context, params));
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters4 params) throws OtrCryptoException {
        context.setState(new StateEncrypted4(context, params));
    }

    @Override
    public void end(@Nonnull final Context context) {
        // already in "ended" state
    }
}
