/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.api;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

/**
 * Utility class for safely handling the processing of OtrEngineListener
 * listeners.
 */
@SuppressWarnings("PMD.AvoidCatchingGenericException")
public final class OtrEngineListenerUtil {

    private static final Logger LOGGER = Logger.getLogger(OtrEngineListenerUtil.class.getName());

    private OtrEngineListenerUtil() {
        // static methods only. No need to instantiate this utility class.
    }

    /**
     * Thread-safely duplicate list of OtrEngineListener listeners.
     *
     * The duplicated list can be used to safely iterate over without the need
     * of locking the original list instance. That means that there is no risk
     * of ConcurrentModificationException. This list is a momentary snapsnot and
     * will not reflect updates/modifications on the original list.
     *
     * @param listeners Original list of listeners that, additionally, must be
     * handled thread-safely.
     * @return Returns duplicated list of listeners. (For one-time use.)
     */
    public static List<OtrEngineListener> duplicate(@Nonnull final List<OtrEngineListener> listeners) {
        synchronized (listeners) {
            return new ArrayList<>(listeners);
        }
    }

    /**
     * Safely call sessionStatusChanged on all listeners in provided iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     * @param receiver The receiver instance.
     */
    public static void sessionStatusChanged(@Nonnull final Iterable<OtrEngineListener> listeners,
            @Nonnull final SessionID sessionID, @Nonnull final InstanceTag receiver) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a
                // service to the user we log any problems that occur while
                // calling listeners.
                l.sessionStatusChanged(sessionID, receiver);
            } catch (final RuntimeException e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'sessionStatusChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }

    /**
     * Safely call multipleInstancesDetected on all listeners in provided
     * iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     */
    public static void multipleInstancesDetected(@Nonnull final Iterable<OtrEngineListener> listeners,
            @Nonnull final SessionID sessionID) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a
                // service to the user we log any problems that occur while
                // calling listeners.
                l.multipleInstancesDetected(sessionID);
            } catch (RuntimeException e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'multipleInstancesDetected' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }

    /**
     * Safely call outgoingSessionChanged on all listeners in provided iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     */
    public static void outgoingSessionChanged(@Nonnull final Iterable<OtrEngineListener> listeners,
            @Nonnull final SessionID sessionID) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a
                // service to the user we log any problems that occur while
                // calling listeners.
                l.outgoingSessionChanged(sessionID);
            } catch (RuntimeException e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'outgoingSessionChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }
}
