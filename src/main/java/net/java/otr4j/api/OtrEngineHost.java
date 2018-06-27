/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.io.messages.ClientProfilePayload;

import javax.annotation.Nonnull;
import java.security.KeyPair;

/**
 * This interface should be implemented by the host application. It is required
 * for otr4j to work properly. This provides the core interface between the app
 * and otr4j.
 *
 * @author George Politis
 */
// TODO consider splitting up the OTRv3 and OTRv4 EngineHost interfaces such that one can use random instance tags and the other queries the host.
public interface OtrEngineHost extends SmpEngineHost {

    /**
     * Request host to inject a new message into the IM communication stream
     * upon which the OTR session is built.
     *
     * @param sessionID The session ID
     * @param msg The message to inject
     */
    void injectMessage(@Nonnull SessionID sessionID, @Nonnull String msg);

    /**
     * Warn the user that an encrypted message was received that could not be
     * decrypted, most likely because it was encrypted to a different session,
     * or an old session.
     *
     * @param sessionID The session ID
     */
    void unreadableMessageReceived(@Nonnull SessionID sessionID);

    /**
     * Display the message to the user, but warn him that the message was
     * received decrypted.
     *
     * @param sessionID The session ID
     * @param msg the body of the received message that was not encrypted
     */
    void unencryptedMessageReceived(@Nonnull SessionID sessionID, @Nonnull String msg);

    /**
     * Ask Engine Host to show provided error message that was received over
     * OTR.
     *
     * @param sessionID the session ID
     * @param error the error message
     */
    void showError(@Nonnull SessionID sessionID, @Nonnull String error);

    /**
     * Signal Engine Host that OTR secure session is finished.
     *
     * @param sessionID the session ID
     * @param msgText message text
     */
    void finishedSessionMessage(@Nonnull SessionID sessionID, @Nonnull String msgText);

    /**
     * Signal Engine Host that current policy dictates that a secure session is
     * required for messages to be sent.
     *
     * @param sessionID the session ID
     * @param msgText the encryption required message
     */
    void requireEncryptedMessage(@Nonnull SessionID sessionID, @Nonnull String msgText);

    /**
     * Request the current session policy for provided session ID.
     *
     * @param sessionID the session ID
     * @return Returns the current policy for specified session.
     */
    OtrPolicy getSessionPolicy(@Nonnull SessionID sessionID);

    /**
     * Get instructions for the necessary fragmentation operations.
     *
     * If no fragmentation is necessary, return {@link Integer#MAX_VALUE} to
     * indicate the largest possible fragment size. Return any positive
     * integer to specify a maximum fragment size and enable fragmentation
     * using that boundary condition. If specified max fragment size is too
     * small to fit at least the fragmentation overhead + some part of the
     * message, fragmentation will fail with an IOException when
     * fragmentation is attempted during message encryption.
     *
     * @param sessionID
     *            the session ID of the session
     * @return Returns the maximum fragment size allowed. Or return the
     * maximum value possible, {@link Integer#MAX_VALUE}, if fragmentation
     * is not necessary.
     */
    int getMaxFragmentSize(@Nonnull SessionID sessionID);

    /**
     * Request local key pair from Engine Host. (OTRv2/OTRv3)
     *
     * @param sessionID the session ID
     * @return Returns the local key pair.
     */
    @Nonnull
    KeyPair getLocalKeyPair(@Nonnull SessionID sessionID);

    /**
     * Request local long-term key pair from Engine Host. (OTRv4)
     *
     * @param sessionID the session ID
     * @return Returns the local long-term Ed448-goldilocks key pair.
     */
    @Nonnull
    EdDSAKeyPair getLongTermKeyPair(@Nonnull SessionID sessionID);

    /**
     * Request the client's Client Profile.
     *
     * The client profile is requested from the OTR engine host. The session ID is provided as a parameter to indicate
     * for which session a client profile is requested. The session ID can be used to distinguish between different
     * networks or users, such that it becomes possible to return one of many possible client profiles, based on the
     * current session.
     *
     * @param sessionID The session ID for which the Client Profile is requested.
     * @return Returns the Client Profile for this client.
     */
    @Nonnull
    ClientProfilePayload getClientProfile(@Nonnull SessionID sessionID);

    /**
     * Request local fingerprint in raw byte form.
     *
     * @param sessionID the session ID
     * @return Returns the raw fingerprint bytes.
     */
    @Override
    @Nonnull
    byte[] getLocalFingerprintRaw(@Nonnull SessionID sessionID);

    /**
     * When a message is received that is unreadable for some reason, for
     * example the session keys are lost/deleted already, then the Engine Host
     * is asked to provide a suitable reply to send back as an OTR error
     * message.
     *
     * @param sessionID the session ID
     * @return Returns an error message.
     */
    String getReplyForUnreadableMessage(@Nonnull SessionID sessionID);

    /**
     * Return the localized message that explains to the recipient how to get an
     * OTR-enabled client. This is sent as part of the initial OTR Query message
     * that prompts the other side to set up an OTR session. If this returns
     * {@code null} or {@code ""}, then otr4j will use the built-in default
     * message specified in SerializationConstants#DEFAULT_FALLBACK_MESSAGE.
     *
     * @param sessionID the session ID
     * @return String the localized message
     */
    String getFallbackMessage(@Nonnull SessionID sessionID);

    /**
     * Signal the Engine Host that a message is received that is intended for
     * another instance. The (local) user may have multiple OTR capable chat
     * clients active on this account.
     *
     * @param sessionID the session ID
     */
    void messageFromAnotherInstanceReceived(@Nonnull SessionID sessionID);

    /**
     * Signal the Engine Host that we have received a message that is intended
     * for us, but is sent from another instance. Our chat buddy may be logged
     * in at multiple locations.
     *
     * @param sessionID the session ID
     */
    void multipleInstancesDetected(@Nonnull SessionID sessionID);

    /**
     * Report on discovery of extra symmetric key in message.
     *
     * @param sessionID The session ID
     * @param message The message that contained TLV 8. (The signal that
     * indicates use of the Extra Symmetric Key)
     * @param extraSymmetricKey The extra symmetric key itself. The key is
     * calculated from the session key matching that of the message that
     * contained TLV 8.
     * @param tlvData The data embedded in TLV 8.
     */
    void extraSymmetricKeyDiscovered(@Nonnull final SessionID sessionID, @Nonnull final String message, @Nonnull final byte[] extraSymmetricKey, @Nonnull final byte[] tlvData);
}
