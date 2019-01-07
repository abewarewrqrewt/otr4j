/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;

/**
 * Interface to the Message state.
 */
// TODO the whole class-hierarchy of implementation logic is not very easy to reason about. See if we can get rid of it.
public interface State {

    /**
     * Constant to indicate that no flag bit is set.
     */
    byte FLAG_NONE = 0x00;

    /**
     * Constant for the flag IGNORE_UNREADABLE, which is used to indicate that if such a flagged message cannot be read,
     * we do not need to respond with an error message.
     */
    byte FLAG_IGNORE_UNREADABLE = 0x01;

    /**
     * Get active protocol version.
     *
     * @return Returns protocol version that is active in this session state.
     * (0 for plaintext/finished, OTR version for ENCRYPTED message state.)
     */
    int getVersion();

    /**
     * Get session status for currently active session.
     *
     * @return Returns session status.
     */
    @Nonnull
    SessionStatus getStatus();

    /**
     * Get remote public key.
     *
     * @return Returns the remote public key.
     * @throws IncorrectStateException Throws IncorrectStateException in any
     * non-encrypted state, since no public key is available there.
     */
    @Nonnull
    DSAPublicKey getRemotePublicKey() throws IncorrectStateException;

    /**
     * Acquire the extra symmetric key for this session.
     *
     * @return Returns the extra symmetric key that is derived from the
     * session's shared secret.
     * @throws IncorrectStateException Throws exception in case of incorrect
     * state, i.e. a different state than ENCRYPTED.
     */
    @Nonnull
    byte[] getExtraSymmetricKey() throws IncorrectStateException;

    /**
     * Transforms a message ready to be sent given the current session state of
     * OTR.
     *
     * @param context The message state context.
     * @param msgText The message ready to be sent.
     * @param tlvs    TLVs.
     * @param flags   (Encoded) message flags, see constants in {@link State}, such as {@link #FLAG_IGNORE_UNREADABLE}.
     * @return Returns message to be sent over IM transport.
     * @throws OtrException In case an exception occurs.
     */
    @Nullable
    Message transformSending(@Nonnull Context context, @Nonnull String msgText, @Nonnull Iterable<TLV> tlvs,
            final byte flags) throws OtrException;

    /**
     * Handle the received plaintext message.
     *
     * @param context          The message state context.
     * @param plainTextMessage The received plaintext message.
     * @return Returns the cleaned plaintext message. (The message excluding
     * possible whitespace tags or other OTR artifacts.)
     */
    @Nonnull
    String handlePlainTextMessage(@Nonnull final Context context, @Nonnull PlainTextMessage plainTextMessage);

    /**
     * Handle the received encoded message.
     *
     * @param context The message state context.
     * @param message the encoded message
     * @return Returns decoded, decrypted plaintext message payload, if exists, or {@code null} otherwise.
     * @throws OtrException In case of failure to process encoded message.
     */
    // TODO be more specific for OtrException, distinguish between message ignoring and actually throwing exception.
    @Nullable
    String handleEncodedMessage(@Nonnull final Context context, @Nonnull EncodedMessage message) throws OtrException;

    /**
     * Get current authentication state from the AKE state machine.
     *
     * @return current authentication state
     */
    @Nonnull
    AuthState getAuthState();

    /**
     * Set authentication state for the AKE state machine.
     *
     * @param state the new authentication state
     */
    void setAuthState(@Nonnull AuthState state);

    /**
     * Initiate AKE.
     *
     * @param context             The message state context.
     * @param version             the protocol version
     * @param receiverInstanceTag the receiver instance tag to be targeted, or {@link InstanceTag#ZERO_TAG} if unknown.
     * @param queryTag            the query tag to which we respond
     * @return Returns the encoded message initiating the AKE, either DH-Commit (OTRv2/OTRv3) or Identity message (OTRv4).
     */
    @Nonnull
    AbstractEncodedMessage initiateAKE(@Nonnull final Context context, int version, InstanceTag receiverInstanceTag,
            String queryTag);

    /**
     * Handle the received error message.
     *
     * @param context      The message state context.
     * @param errorMessage The error message.
     * @throws OtrException In case an exception occurs.
     */
    void handleErrorMessage(@Nonnull final Context context, @Nonnull ErrorMessage errorMessage) throws OtrException;

    /**
     * Call to end encrypted session, if any.
     * <p>
     * In case an encrypted session is established, this is the moment where the final MAC codes are revealed as part of
     * the TLV DISCONNECT message.
     *
     * @param context The message state context.
     * @throws OtrException In case an exception occurs.
     */
    void end(@Nonnull final Context context) throws OtrException;

    /**
     * Get SMP TLV handler for use in SMP negotiations.
     *
     * The handler is only available in Encrypted states. In case another state
     * is active at time of calling, {@link IncorrectStateException} is thrown.
     *
     * @return Returns SMP TLV handler instance for this encrypted session.
     * @throws IncorrectStateException Throws IncorrectStateException for any
     * non-encrypted states.
     */
    @Nonnull
    SMPHandler getSmpHandler() throws IncorrectStateException;

    /**
     * Securely clear the content of the state after {@link Context#transition(State, State)}-ing away from it.
     */
    void destroy();
}
