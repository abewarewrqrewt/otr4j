package net.java.otr4j.session.smpv4;

import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;

/**
 * The interface defining the state machine capabilities, as per the State pattern.
 */
interface SMPState {

    /**
     * Get the current status of the SMP state machine.
     *
     * @return Returns the current status.
     */
    @Nonnull
    SMPStatus getStatus();

    /**
     * Initiate a new SMP negotiation.
     * <p>
     * This may be called at any time. If a SMP negotiation is already in progress, it will be aborted.
     *
     * @param context  the SMP context
     * @param question the question posed to the other party
     * @param secret   the secret MPI derived from the user-supplied answer
     * @return Returns the SMP initiating message to be included as TLV payload in a data message.
     */
    @Nonnull
    SMPMessage1 initiate(@Nonnull SMPContext context, @Nonnull String question, @Nonnull BigInteger secret);

    /**
     * Respond to SMP initiation request with response based on our own secret answer.
     * <p>
     * The question is repeated here to ensure that the answer corresponds to the currently known question. If the
     * question mismatches with the currently known question, then this answer is ignored to ensure that we do not
     * follow the SMP negotiation based on a wrong answer.
     *
     * @param context  the SMP context
     * @param question the question posed by the other party to which we are providing the answer.
     * @param secret   the secret MPI derived from the user-supplied answer
     * @return Returns SMP response message to be included as TLV payload in a data message.
     */
    @Nullable
    SMPMessage2 respondWithSecret(@Nonnull SMPContext context, @Nonnull String question, @Nonnull BigInteger secret);

    /**
     * Process a (non-initial) SMP message.
     *
     * @param context the SMP context
     * @param message the message
     * @return Returns the response to the received message.
     * @throws SMPAbortException In case of an unexpected message, the protocol gets reset to the initial state.
     */
    @Nullable
    SMPMessage process(@Nonnull SMPContext context, @Nonnull SMPMessage message) throws SMPAbortException;
}
