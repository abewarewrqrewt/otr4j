/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

/**
 * General OTR exception type.
 * <p>
 * This is the generic exception type for any type of exception that may occur in otr4j.
 */
public class OtrException extends Exception {

    private static final long serialVersionUID = -6327624437614707245L;

    /**
     * Constructor.
     *
     * @param message the message
     */
    public OtrException(final String message) {
        super(message);
    }

    /**
     * Constructor.
     *
     * @param message the message
     * @param cause   the cause
     */
    public OtrException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
