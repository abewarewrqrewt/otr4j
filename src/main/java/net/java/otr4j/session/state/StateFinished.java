/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.DataMessage4;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.PublicKey;
import java.util.List;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.OtrEngineHostUtil.finishedSessionMessage;
import static net.java.otr4j.api.OtrEngineHostUtil.getReplyForUnreadableMessage;
import static net.java.otr4j.api.OtrEngineHostUtil.unencryptedMessageReceived;
import static net.java.otr4j.api.OtrEngineHostUtil.unreadableMessageReceived;

/**
 * Message state FINISHED. This message state is initiated through events
 * started from the initial message state PLAINTEXT (and transition through
 * ENCRYPTED).
 *
 * @author Danny van Heumen
 */
final class StateFinished extends AbstractState {

    private final SessionID sessionId;

    StateFinished(final SessionID sessionId) {
        super();
        this.sessionId = requireNonNull(sessionId);
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
        return SessionStatus.FINISHED;
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available in finished state.");
    }

    @Override
    @Nonnull
    public PublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available in finished state.");
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available in finished state.");
    }

    @Override
    @Nonnull
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) {
        // Display the message to the user, but warn him that the message was received unencrypted.
        unencryptedMessageReceived(context.getHost(), sessionId, plainTextMessage.getCleanText());
        return plainTextMessage.getCleanText();
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
    @Nullable
    public Message transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) {
        finishedSessionMessage(context.getHost(), sessionId, msgText);
        return null;
    }

    @Override
    public void end(@Nonnull final Context context) {
        context.setState(new StatePlaintext(this.sessionId));
    }
}
