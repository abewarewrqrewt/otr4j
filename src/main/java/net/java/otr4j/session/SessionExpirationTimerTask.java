/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.session.state.IncorrectStateException;

import javax.annotation.Nonnull;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.TimerTask;
import java.util.logging.Logger;

import static java.util.Collections.synchronizedList;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.WARNING;

// FIXME Consider transitioning expired sessions to FINISHED instead of START such that inconvenient expirations do not unintendedly reveal user messages. (https://github.com/otrv4/otrv4/blob/master/otrv4.md#session-expiration)
// FIXME Review logic from the perspective of multi-threaded processing, taking into account use of Session instance.
final class SessionExpirationTimerTask extends TimerTask {

    private static final Logger LOGGER = Logger.getLogger(SessionExpirationTimerTask.class.getName());

    private static final SessionExpirationTimerTask INSTANCE = new SessionExpirationTimerTask();

    // FIXME set sensible expiration offset (now 60 ms, is not functional)
    private static final long SESSION_EXPIRATION_OFFSET_NANOSECONDS = 7200_000_000_000L;

    private final List<WeakReference<SessionImpl>> registry = synchronizedList(new ArrayList<WeakReference<SessionImpl>>());

    private SessionExpirationTimerTask() {
        // No further initialization needed.
    }

    static SessionExpirationTimerTask instance() {
        return INSTANCE;
    }

    void register(@Nonnull final SessionImpl session) {
        this.registry.add(new WeakReference<>(session));
    }

    @Override
    public void run() {
        final ArrayList<WeakReference<SessionImpl>> duplicatedRegistry;
        synchronized (this.registry) {
            duplicatedRegistry = new ArrayList<>(this.registry);
        }
        final long now = System.nanoTime();
        for (final WeakReference<SessionImpl> ref : duplicatedRegistry) {
            final SessionImpl master = ref.get();
            if (master == null) {
                // TODO we should remove references once they have been GCed.
                continue;
            }
            checkExpireSession(now, master);
            for (SessionImpl slave : master.getInstances()) {
                checkExpireSession(now, slave);
            }
        }
    }

    private void checkExpireSession(final long now, @Nonnull final SessionImpl session) {
        try {
            if (now - session.getLastActivity() > SESSION_EXPIRATION_OFFSET_NANOSECONDS) {
                LOGGER.log(FINE, "Expiring session " + session.getSessionID() + " (" + session.getSenderInstanceTag() + ")");
                session.expireSession();
            }
        } catch (final IncorrectStateException e) {
            LOGGER.finest("Session instance's current state does not expire.");
        } catch (final OtrException e) {
            LOGGER.log(WARNING, "Failure while expiring session instance.", e);
        }
    }
}
