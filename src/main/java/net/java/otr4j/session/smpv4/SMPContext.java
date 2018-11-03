/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smpv4;

import javax.annotation.Nonnull;

/**
 * The SMP context object, as specified by the State pattern, provides access to the context of the SMP state machine.
 */
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
