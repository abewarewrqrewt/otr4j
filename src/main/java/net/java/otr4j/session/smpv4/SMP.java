package net.java.otr4j.session.smpv4;

import net.java.otr4j.api.TLV;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.session.smpv4.SMPStatus.UNDECIDED;

/**
 * OTRv4 variant of the Socialist Millionaire's Protocol.
 */
public final class SMP implements SMPContext {

    private static final Logger LOGGER = Logger.getLogger(SMP.class.getName());

    private final SecureRandom random;

    private SMPState state;

    /**
     * Constructor for SMP implementation.
     *
     * @param random SecureRandom instance
     */
    public SMP(@Nonnull final SecureRandom random) {
        this.random = requireNonNull(random);
        this.state = new StateExpect1(random, UNDECIDED);
    }

    @Override
    public void setState(@Nonnull final SMPState newState) {
        this.state = requireNonNull(newState);
        LOGGER.log(Level.FINE, "SMP transitioning to state {0}", newState);
    }

    /**
     * Get the current SMP state machine status.
     *
     * @return Returns the status.
     */
    public SMPStatus getStatus() {
        return this.state.getStatus();
    }

    /**
     * Initiate a new SMP negotiation.
     *
     * @param question the question
     * @param secret   the secret, i.e. the answer to the posed question
     * @return Returns an OtrEncodable to be sent to the other party.
     */
    @Nonnull
    public TLV initiate(@Nonnull final String question, @Nonnull final byte[] secret) {
        // FIXME implement SMP initiation
        throw new UnsupportedOperationException("To be implemented");
    }

    /**
     * Process an SMP TLV payload.
     *
     * @param tlv the SMP tlv
     * @return Returns an OtrEncodable with the response to SMP message 1.
     */
    @Nullable
    public TLV process(@Nonnull final TLV tlv) {
        // FIXME implement processing SMP message 1
        throw new UnsupportedOperationException("To be implemented");
    }

    /**
     * Abort an in-progress SMP negotiation.
     */
    public void abort() {
        setState(new StateExpect1(this.random, UNDECIDED));
    }
}
