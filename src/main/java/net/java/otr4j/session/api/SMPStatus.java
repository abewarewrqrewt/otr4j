/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.api;

/**
 * Statuses in SMP negotiation.
 */
public enum SMPStatus {
    /**
     * Status is undecided. No SMP exchange has started.
     */
    UNDECIDED,
    /**
     * SMP exchange is in progress. (First message has arrived/is sent.)
     */
    INPROGRESS,
    /**
     * SMP exchange final state for normal cases. SMP exchange has been
     * fully completed and it has succeeded, i.e. with positive outcome.
     */
    SUCCEEDED,
    /**
     * SMP exchange final state for normal cases. SMP exchange has been
     * completed, but with negative outcome.
     */
    FAILED,
    /**
     * SMP exchange final state for exceptional cases. This might indicate
     * that invalid message were sent on purpose to play the protocol and as
     * a consequence processing did not finish as expected.
     */
    CHEATED
}
