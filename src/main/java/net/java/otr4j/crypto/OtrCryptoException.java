/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.crypto;

import net.java.otr4j.api.OtrException;

/**
 * Exception for issues w.r.t. crypto operations in otr4j.
 */
public final class OtrCryptoException extends OtrException {

    private static final long serialVersionUID = -2636945817636034632L;

    OtrCryptoException(final String message) {
        super(message);
    }

    OtrCryptoException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
