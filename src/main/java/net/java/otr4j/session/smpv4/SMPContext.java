package net.java.otr4j.session.smpv4;

import javax.annotation.Nonnull;

interface SMPContext {

    /**
     * Set new SMP state as current state.
     *
     * @param newState the new SMP state
     */
    void setState(@Nonnull SMPState newState);

    /**
     * Request the user for the answer to the question that is posed by the other party.
     *
     * @param question the question
     */
    void requestSecret(@Nonnull String question);
}
