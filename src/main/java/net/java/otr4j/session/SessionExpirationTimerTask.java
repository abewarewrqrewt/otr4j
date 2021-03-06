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
import java.util.Iterator;
import java.util.List;
import java.util.TimerTask;
import java.util.logging.Logger;

import static java.util.Collections.synchronizedList;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.WARNING;

final class SessionExpirationTimerTask extends TimerTask {

    private static final Logger LOGGER = Logger.getLogger(SessionExpirationTimerTask.class.getName());

    private static final SessionExpirationTimerTask INSTANCE = new SessionExpirationTimerTask();

    private static final long SESSION_TIMEOUT_NANOSECONDS = 7200_000_000_000L;

    private final List<WeakReference<SessionImpl>> registry = synchronizedList(new ArrayList<WeakReference<SessionImpl>>());

    private SessionExpirationTimerTask() {
        super();
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
        final Iterator<WeakReference<SessionImpl>> it = duplicatedRegistry.iterator();
        while (it.hasNext()) {
            final SessionImpl master = it.next().get();
            if (master == null) {
                it.remove();
                continue;
            }
            expireTimedOutSessions(now, master);
            for (final SessionImpl slave : master.getInstances()) {
                expireTimedOutSessions(now, slave);
            }
        }
    }

    private void expireTimedOutSessions(final long now, @Nonnull final SessionImpl session) {
        try {
            if (now - session.getLastActivityTimestamp() > SESSION_TIMEOUT_NANOSECONDS) {
                LOGGER.log(FINE, "Expiring session " + session.getSessionID() + " (" + session.getSenderInstanceTag() + ")");
                session.expireSession();
            }
        } catch (final IncorrectStateException e) {
            // TODO add session identifier (and instance tag) to make clear which session is referenced
            LOGGER.finest("Session instance's current state does not expire.");
        } catch (final OtrException e) {
            LOGGER.log(WARNING, "Failure while expiring session instance.", e);
        }
    }
}
