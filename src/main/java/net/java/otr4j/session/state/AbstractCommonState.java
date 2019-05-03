/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.logging.Logger;

import static net.java.otr4j.api.OtrEngineHosts.requireEncryptedMessage;
import static net.java.otr4j.api.OtrEngineHosts.showError;
import static net.java.otr4j.session.state.Contexts.signalUnreadableMessage;

abstract class AbstractCommonState extends AbstractOTR4State {

    private static final Logger LOGGER = Logger.getLogger(AbstractCommonState.class.getName());

    AbstractCommonState(@Nonnull final AuthState authState) {
        super(authState);
    }

    @Nonnull
    @Override
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) {
        return plainTextMessage.getCleanText();
    }

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage)
            throws OtrException {
        showError(context.getHost(), context.getSessionID(), errorMessage.error);
    }

    void handleUnreadableMessage(@Nonnull final Context context, @Nonnull final DataMessage message,
            @Nonnull final String identifier, @Nonnull final String error)
            throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context, identifier, error);
    }

    void handleUnreadableMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message,
            @Nonnull final String identifier, @Nonnull final String error)
            throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context, identifier, error);
    }

    /**
     * Implementation of {@code transformSending(Context, String, List, byte)} that prevents sending messages as we have
     * not yet transitioned into `ENCRYPTED_MESSAGES` state.
     *
     * @param context The message state context.
     * @param msgText The message to be sent.
     * @param tlvs    List of TLVs to attach to the message.
     * @param flags   (Encoded) message flags, see constants in {@link State}, such as {@link #FLAG_IGNORE_UNREADABLE}.
     * @return Returns null as there is nothing to send immediately.
     * @throws OtrException In case an exception occurs.
     */
    @Nullable
    @Override
    public Message transformSending(@Nonnull final Context context, @Nonnull final String msgText,
            @Nonnull final Iterable<TLV> tlvs, final byte flags) throws OtrException {
        requireEncryptedMessage(context.getHost(), context.getSessionID(), msgText);
        return null;
    }

    @Override
    public void expire(@Nonnull final Context context) throws OtrException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " does not expire.");
    }

    @Override
    public long getLastActivityTimestamp() throws IncorrectStateException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " does not expire.");
    }

    @Override
    public long getLastMessageSentTimestamp() throws IncorrectStateException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " is not an encrypted state.");
    }
}
