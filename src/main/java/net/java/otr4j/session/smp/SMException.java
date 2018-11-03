/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smp;

/**
 * Exception indicating a problem during execution of the Socialist Millionaire Protocol.
 */
public class SMException extends Exception {

    private static final long serialVersionUID = 6707119807502537414L;

    SMException(final Throwable cause) {
        super(cause);
    }

    SMException(final String message) {
        super(message);
    }

    SMException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
