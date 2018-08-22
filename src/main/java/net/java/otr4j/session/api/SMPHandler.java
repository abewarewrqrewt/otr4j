package net.java.otr4j.session.api;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Handler for Socialist Millionaire's Protocol messages.
 * <p>
 * NOTE: this API should not be used by users of the otr4j library.
 */
public interface SMPHandler {

    /**
     * Initiate a new SMP negotiation.
     * <p>
     * NOTE: Initiating a new SMP negotiation after a previous SMP session has completed will obsolete the previous
     * result.
     *
     * @param question the question to be posed
     * @param answer   our answer to the question, to be used in the zero-knowledge proof
     * @return Returns the TLV that will request initiation of SMP.
     * @throws OtrException In case of issues while initiating SMP.
     */
    // FIXME check if this OtrException is really needed.
    @Nonnull
    TLV initiate(@Nonnull final String question, @Nonnull final byte[] answer) throws OtrException;

    /**
     * Respond to SMP negotiation initiated by the other party.
     *
     * @param question the original question
     * @param answer   the our answer to the question
     * @return Returns TLV with response.
     * @throws OtrException In case of issues while responding.
     */
    @Nullable
    TLV respond(@Nonnull final String question, @Nonnull final byte[] answer) throws OtrException;

    /**
     * Check whether a SMP negotiation is in progress.
     *
     * @return Returns true iff negotiation is in progress.
     */
    @CheckReturnValue
    boolean isInProgress();

    /**
     * Abort an existing SMP negotiation.
     *
     * @return TLV containing abort message.
     */
    @Nullable
    TLV abort();
}
