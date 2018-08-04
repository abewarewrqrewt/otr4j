/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Utilities for SmpEngineHost.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("PMD.AvoidCatchingGenericException")
public final class SmpEngineHostUtil {

    private static final Logger LOGGER = Logger.getLogger(SmpEngineHostUtil.class.getName());

    private SmpEngineHostUtil() {
        // No need to instantiate utility class.
    }

    /**
     * Signal Engine Host to ask user for the secret answer for the provided question.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param sender the sender instance tag
     * @param question The question sent by the other party.
     */
    public static void askForSecret(@Nonnull final SmpEngineHost host,
            @Nonnull final SessionID sessionID, @Nonnull final InstanceTag sender,
            @Nullable final String question) {
        try {
            host.askForSecret(sessionID, sender, question);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'askForSecret' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'smpError' on Engine Host. In case of runtime exception a
     * warning will be logged and execution will continue. By logging the
     * exception and continuing we ensure that the SMP error will be handled
     * fully and the session correctly ended, even if something went wrong on
     * the Engine Host.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param tlvType the TLV type
     * @param cheated indicator for nature of SMP error, whether error because
     * of "cheat" status or for other reason.
     */
    public static void smpError(@Nonnull final SmpEngineHost host, @Nonnull final SessionID sessionID,
            final int tlvType, final boolean cheated) {
        try {
            host.smpError(sessionID, tlvType, cheated);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'smpError' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'smpAborted' on Engine Host. In case of runtime exception a
     * warning will be logged and execution will continue. By logging the
     * exception and continuing we ensure that the SMP abort will be handled
     * fully and the session correctly ended, even if something went wrong on
     * the Engine Host.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host The SMP engine host
     * @param sessionID The session ID
     */
    public static void smpAborted(@Nonnull final SmpEngineHost host, @Nonnull final SessionID sessionID) {
        try {
            host.smpAborted(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'smpAborted' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'verify' on Engine Host. In case of runtime exception an
     * error will be logged and execution will continue. By logging the error
     * and continuing we ensure that the protocol interaction for the current
     * session will continue as expected, even if something went wrong on the
     * Engine Host in registering the successful verification.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param fingerprint the fingerprint of the verified chat partner
     */
    public static void verify(@Nonnull final SmpEngineHost host,
            @Nonnull final SessionID sessionID,
            @Nonnull final String fingerprint) {
        try {
            host.verify(sessionID, fingerprint);
        } catch (RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Faulty OtrEngineHost! Runtime exception thrown while calling 'verify' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'unverify' on Engine Host. In case of runtime exception an
     * error will be logged and execution will continue. By logging the error
     * and continuing we ensure that the protocol interaction for the current
     * session will continue as expected, even if something went wrong on the
     * Engine Host in registering the unsuccessful verification.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param fingerprint the fingerprint of the unverified chat partner
     */
    public static void unverify(@Nonnull final SmpEngineHost host,
            @Nonnull final SessionID sessionID, @Nonnull final String fingerprint) {
        try {
            host.unverify(sessionID, fingerprint);
        } catch (RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Faulty OtrEngineHost! Runtime exception thrown while calling 'unverify' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }
}
