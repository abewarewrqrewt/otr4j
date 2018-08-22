package net.java.otr4j.session.smpv4;

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
    FAILED;
}
