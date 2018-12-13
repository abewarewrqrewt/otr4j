/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.AuthState;

import javax.annotation.Nonnull;

import java.util.logging.Logger;

import static net.java.otr4j.api.OtrEngineHostUtil.showError;
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

    void handleUnreadableMessage(@Nonnull final Context context, @Nonnull final DataMessage message)
            throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context);
    }

    void handleUnreadableMessage(@Nonnull final Context context, @Nonnull final DataMessage4 message)
            throws OtrException {
        if ((message.getFlags() & FLAG_IGNORE_UNREADABLE) == FLAG_IGNORE_UNREADABLE) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context);
    }
}
