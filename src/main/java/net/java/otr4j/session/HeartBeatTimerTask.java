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

final class HeartBeatTimerTask extends TimerTask {

    private static final Logger LOGGER = Logger.getLogger(HeartBeatTimerTask.class.getName());

    private static final long IDLENESS_THRESHOLD_NANOSECONDS = 60_000_000_000L;

    private static final HeartBeatTimerTask INSTANCE = new HeartBeatTimerTask();

    private final List<WeakReference<SessionImpl>> registry = synchronizedList(new ArrayList<WeakReference<SessionImpl>>());

    private HeartBeatTimerTask() {
        super();
    }

    static HeartBeatTimerTask instance() {
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
            sendHeartbeatOnIdleness(now, master);
            for (final SessionImpl slave : master.getInstances()) {
                sendHeartbeatOnIdleness(now, slave);
            }
        }
    }

    private void sendHeartbeatOnIdleness(final long now, @Nonnull final SessionImpl session) {
        try {
            if (now - session.getLastMessageSentTimestamp() > IDLENESS_THRESHOLD_NANOSECONDS) {
                LOGGER.log(FINE, "Sending heartbeat for session " + session.getSessionID() + " (" + session.getSenderInstanceTag() + ")");
                session.sendHeartbeat();
            }
        } catch (final IncorrectStateException e) {
            // TODO add session identifier (and instance tag) to make clear which session is referenced
            LOGGER.finest("Session instance's current state is not a private messaging state.");
        } catch (final OtrException e) {
            LOGGER.log(WARNING, "Failure while sending heartbeat for session instance.", e);
        }
    }
}
