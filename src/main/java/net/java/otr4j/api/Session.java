/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.api;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface Session {

    // TODO consider converting this to an enum, and EnumSet for SUPPORTED, KNOWN versions.
    interface OTRv {

        int ONE = 1;
        int TWO = 2;
        int THREE = 3;
        int FOUR = 4;

        // TODO in time remove support for OTR version 2.
        Set<Integer> SUPPORTED = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(TWO, THREE, FOUR)));
        Set<Integer> KNOWN = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(ONE, TWO, THREE, FOUR)));
    }

    /* Methods that provide session information. */

    /**
     * Get the session ID for the session.
     *
     * @return Returns the session ID.
     */
    @Nonnull
    SessionID getSessionID();

    /**
     * Get current outgoing session's status.
     *
     * @return Returns session status.
     */
    @Nonnull
    SessionStatus getSessionStatus();

    /**
     * Get current session status for a particular receiver instance.
     *
     * @param tag the receiver instance tag
     * @return Returns session status.
     */
    @Nonnull
    SessionStatus getSessionStatus(@Nonnull InstanceTag tag);

    /**
     * Get session policy.
     *
     * @return session policy
     */
    @Nonnull
    OtrPolicy getSessionPolicy();

    /**
     * Get status of offering OTR through whitespace tags.
     *
     * @return Returns status of whitespace offer.
     */
    @Nonnull
    OfferStatus getOfferStatus();

    /**
     * Get protocol version for active session.
     *
     * @return Returns protocol version or 0 in case of no session active.
     */
    int getProtocolVersion();

    /**
     * Get sender instance tag.
     *
     * @return Returns sender instance tag.
     */
    @Nonnull
    InstanceTag getSenderInstanceTag();

    /**
     * Get receiver instance tag.
     *
     * @return Returns receiver instance tag or 0 in case of OTRv2 session /
     * OTRv3 master session instance.
     */
    @Nonnull
    InstanceTag getReceiverInstanceTag();

    /**
     * Get remote's long-term public key.
     *
     * @return Returns long-term public key.
     * @throws OtrException Thrown in case message state is not ENCRYPTED, hence
     * no long-term public key is known.
     */
    @Nonnull
    PublicKey getRemotePublicKey() throws OtrException;

    /**
     * Get remote's long-term public key.
     *
     * @param tag receiver instance tag
     * @return Returns long-term public key.
     * @throws OtrException Thrown in case message state is not ENCRYPTED, hence
     * no long-term public key is known.
     */
    @Nonnull
    PublicKey getRemotePublicKey(@Nonnull InstanceTag tag) throws OtrException;

    /**
     * Get list of session instances.
     *
     * @return Returns list of session instances.
     */
    @Nonnull
    List<? extends Session> getInstances();

    /**
     * Get Extra Symmetric Key that is provided by OTRv3 based on the current Session Keys.
     *
     * @return Returns 256-bit (shared) secret that can be used to start an out-of-band confidential communication channel
     * @throws OtrException In case message status is not ENCRYPTED.
     */
    @Nonnull
    byte[] getExtraSymmetricKey() throws OtrException;

    // Methods related to session use and control.

    /**
     * Start a new OTR session.
     *
     * @throws OtrException Throws exception in case failure to inject Query
     * message.
     */
    void startSession() throws OtrException;

    /**
     * Get outgoing session.
     *
     * @return Returns session instance.
     */
    @Nonnull
    Session getOutgoingSession();

    /**
     * Set outgoing session to instance corresponding to specified receiver
     * instance tag.
     *
     * @param tag receiver instance tag
     * @throws java.util.NoSuchElementException In case instance tag cannot be found.
     */
    void setOutgoingSession(@Nonnull final InstanceTag tag);

    /**
     * Transform message text to prepare for sending which includes possible
     * OTR facilities. This method assumes no TLVs need to be sent.
     *
     * @param msgText plain message content
     * @return Returns OTR-processed (possibly ENCRYPTED) message content in
     * suitable fragments according to host information on the transport
     * fragmentation.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nonnull
    String[] transformSending(@Nonnull final String msgText) throws OtrException;

    /**
     * Transform message text to prepare for sending which includes possible
     * OTR facilities.
     *
     * @param msgText plain message content
     * @param tlvs    any TLV records to be packed with the other message contents.
     * @return Returns OTR-processed (possibly ENCRYPTED) message content in
     * suitable fragments according to host information on the transport
     * fragmentation.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nonnull
    String[] transformSending(@Nonnull String msgText, @Nonnull List<TLV> tlvs) throws OtrException;

    /**
     * Transform (OTR encoded) message to plain text message.
     *
     * @param msgText the (possibly encrypted) raw message content
     * @return Returns the plaintext message content.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nullable
    String transformReceiving(@Nonnull String msgText) throws OtrException;

    /**
     * Refresh an existing OTR session, i.e. perform new AKE. If sufficient
     * information is available about the protocol capabilities of the other
     * party, then we will immediately send an D-H Commit message with the
     * receiver instance tag set to speed up the process and to avoid other
     * instances from being triggered to start AKE.
     *
     * @throws OtrException In case of failed refresh.
     */
    void refreshSession() throws OtrException;

    /**
     * End ENCRYPTED session.
     *
     * @throws OtrException in case of failure to inject OTR message to inform
     *                      counter party. (The transition to PLAINTEXT will
     *                      happen regardless.)
     */
    void endSession() throws OtrException;

    // Methods related to zero-knowledge-based authentication.

    /**
     * Initiate a new SMP negotiation by providing an optional question and a secret.
     *
     * @param question The optional question, may be null.
     * @param secret   The secret that we should verify the other side knows about.
     * @throws OtrException In case of failure during initiation.
     */
    void initSmp(@Nullable String question, @Nonnull String secret) throws OtrException;

    /**
     * Respond to an SMP request for a specific receiver instance tag.
     *
     * @param receiverTag receiver instance tag
     * @param question    The question
     * @param secret      The secret
     * @throws OtrException In case of failure during response.
     */
    void respondSmp(@Nonnull InstanceTag receiverTag, @Nullable String question, @Nonnull String secret) throws OtrException;

    /**
     * Respond to an SMP request for a specific receiver instance tag.
     *
     * @param question    The question
     * @param secret      The secret
     * @throws OtrException In case of failure during response.
     */
    void respondSmp(@Nullable String question, @Nonnull String secret) throws OtrException;

    /**
     * Abort a running SMP negotiation.
     *
     * @throws OtrException In case session is not in ENCRYPTED message state.
     */
    void abortSmp() throws OtrException;

    /**
     * Query if SMP is in progress.
     *
     * @return Returns true if in progress, or false otherwise.
     */
    boolean isSmpInProgress();

    // Methods related to registering OTR engine listeners.

    /**
     * Register OTR engine listener.
     *
     * @param l OTR engine listener instance.
     */
    void addOtrEngineListener(@Nonnull OtrEngineListener l);

    /**
     * Unregister OTR engine listener.
     *
     * @param l OTR engine listener instance.
     */
    void removeOtrEngineListener(@Nonnull OtrEngineListener l);
}
