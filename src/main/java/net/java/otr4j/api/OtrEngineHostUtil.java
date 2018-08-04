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

/**
 * Utils for OtrEngineHost.
 *
 * <p>Methods that do not have a safe-handling counterpart implemented:</p>
 * <ul>
 * <li><i>injectMessage</i>: the OTR protocol depends on messages being injected for the
 * continuation of the process. Silencing any exceptions on this method will
 * silently halt the process which is not desirable.</li>
 *
 * <li><i>getSessionPolicy</i>: the Session policy is required information for further
 * execution. Do not silence such exceptions as they are important for correct
 * operation of the protocol itself.</li>
 *
 * <li><i>getMaxFragmentSize</i>: the fragment size is required for correct
 * functioning of the fragmentation function.</li>
 *
 * <li><i>getLocalKeyPair</i>: acquiring the local key pair is required for
 * continuing execution. There is no use in silencing exceptions that signal
 * problematic error cases.</li>
 *
 * <li><i>getLocalFingerprintRaw</i>: acquiring the local fingerprint is
 * required for continuing execution. There is no use in silencing exceptiosn
 * that signal problematic error cases.</li>
 * </ul>
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("PMD.AvoidCatchingGenericException")
public final class OtrEngineHostUtil {

    private static final Logger LOGGER = Logger.getLogger(OtrEngineHostUtil.class.getName());

    private OtrEngineHostUtil() {
        // static methods only. No need to instantiate this utility class.
    }

    /**
     * Safely call 'messageFromAnotherInstanceReceived' event on provided
     * OtrEngineHost. Catch any runtime exception and log occurrence of the
     * exception and consequently the misbehaving of the OtrEngineHost instance.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     */
    public static void messageFromAnotherInstanceReceived(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID) {
        try {
            host.messageFromAnotherInstanceReceived(sessionID);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'messageFromAnotherInstanceReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'multipleInstancesDetected' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     */
    public static void multipleInstancesDetected(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID) {
        try {
            host.multipleInstancesDetected(sessionID);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'multipleInstancesDetected' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'unencryptedMessageReceived' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     * @param message the received message
     */
    public static void unencryptedMessageReceived(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID, @Nonnull final String message) {
        try {
            host.unencryptedMessageReceived(sessionID, message);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'unencryptedMessageReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'unreadableMessageReceived' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     */
    public static void unreadableMessageReceived(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID) {
        try {
            host.unreadableMessageReceived(sessionID);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'unreadableMessageReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'getFallbackMessage' in order to retrieve customized fallback
     * message for a chat client that does not support OTR. In case of a runtime
     * exception, null will be returned in order to signal to otr4j to use its
     * default fallback message.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     * @return Returns the engine host's customized fallback message or null if
     * request failed with a runtime exception.
     */
    public static String getFallbackMessage(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID) {
        try {
            return host.getFallbackMessage(sessionID);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'getFallbackMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
        return null;
    }

    /**
     * Safely call 'showError' on Engine Host. In case of runtime exception a
     * warning will be logged and execution will continue. By logging the
     * exception and continuing we ensure that the protocol interaction for the
     * current session will continue as expected, even if something went wrong
     * on the Engine Host in showing the error message.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param error the error message
     */
    public static void showError(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID, @Nonnull final String error) {
        try {
            host.showError(sessionID, error);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'showError' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Signal finished session to Engine Host with provided message. Call Engine
     * Host safely and log any runtime exceptions that are thrown.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param msgText a message text about the finished session
     */
    public static void finishedSessionMessage(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID, @Nonnull final String msgText) {
        try {
            host.finishedSessionMessage(sessionID, msgText);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'finishedSessionMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Signal require encryption to Engine Host with provided message. Call
     * Engine Host safely and log any runtime exceptions that are thrown.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param msgText the message
     */
    public static void requireEncryptedMessage(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID, @Nonnull final String msgText) {
        try {
            host.requireEncryptedMessage(sessionID, msgText);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'requireEncryptedMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Query Engine Host to create suitable reply to send back as reply to an
     * unreadable message.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param defaultMessage the default message to use in case call to OtrEngineHost fails
     * @return Returns the reply for unreadable message to send as error to other party.
     */
    public static String getReplyForUnreadableMessage(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID, @Nonnull final String defaultMessage) {
        try {
            return host.getReplyForUnreadableMessage(sessionID);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'getReplyForUnreadableMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
        return defaultMessage;
    }

    /**
     * Callback in case the Extra Symmetric Key is discovered.
     *
     * The extra symmetric key itself is derived from the matching session key
     * for the message that contains TLV 8. For convenience the user's message
     * is also provided. However this message is also returned as it would be
     * normally as a result of transforming a receiving message. The extra
     * symmetric key is provided as a byte-array. Any data embedded in the TLV
     * 8 record is provided.
     *
     * @param host The OTR engine host.
     * @param sessionID The session ID.
     * @param message The user's message (also returned after extraction from
     * OTR encoded message).
     * @param extraSymmetricKey The extra symmetric key as calculated from the
     * session key.
     * @param tlvData The data embedded in TLV 8 which typically gives a hint
     * of how/where the extra symmetric key is used.
     */
    public static void extraSymmetricKeyDiscovered(@Nonnull final OtrEngineHost host,
            @Nonnull final SessionID sessionID, @Nonnull final String message,
            @Nonnull final byte[] extraSymmetricKey, @Nonnull final byte[] tlvData) {
        try {
            host.extraSymmetricKeyDiscovered(sessionID, message, extraSymmetricKey, tlvData);
        } catch (final RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost: Runtime exception thrown while calling 'extraSymmetricKeyDiscovered' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }
}
