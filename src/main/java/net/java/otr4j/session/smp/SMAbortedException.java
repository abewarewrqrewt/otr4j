/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smp;

import javax.annotation.Nonnull;

/**
 * SM Aborted exception indicates that the current SMP exchange is aborted
 * and the state reset to default.
 */
final class SMAbortedException extends SMException {

    private static final long serialVersionUID = 8062094133300893010L;

    private final boolean inProgress;

    /**
     * Constructor for SMAbortedException.
     *
     * @param inProgress Indicates whether status was INPROGRESS before
     * triggering abort.
     * @param message Message
     */
    SMAbortedException(final boolean inProgress, @Nonnull final String message) {
        super(message);
        this.inProgress = inProgress;
    }

    /**
     * Indicates whether an SMP conversation was in progress before it was
     * aborted.
     *
     * @return Returns true if SMP conversation was previously in progress,
     * or false if it was not.
     */
    boolean isInProgress() {
        return this.inProgress;
    }
}
