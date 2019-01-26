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
import net.java.otr4j.io.ErrorMessage;

import javax.annotation.Nonnull;

import static net.java.otr4j.api.OtrEngineHosts.getReplyForUnreadableMessage;
import static net.java.otr4j.api.OtrEngineHosts.unreadableMessageReceived;

/**
 * Utility class for Context interface.
 */
public final class Contexts {

    private static final String DEFAULT_REPLY_UNREADABLE_MESSAGE = "This message cannot be read.";

    private Contexts() {
        // No need to instantiate utility class.
    }

    /**
     * Signal both the local user and the remote party that a message is received that was unreadable.
     *
     * @param context the context instance
     * @throws OtrException In case of failure to inject the remote message into the chat transport.
     */
    public static void signalUnreadableMessage(@Nonnull final Context context) throws OtrException {
        final OtrEngineHost host = context.getHost();
        final SessionID sessionID = context.getSessionID();
        unreadableMessageReceived(host, sessionID);
        final String replymsg = getReplyForUnreadableMessage(host, sessionID, DEFAULT_REPLY_UNREADABLE_MESSAGE);
        context.injectMessage(new ErrorMessage(replymsg));
    }
}
