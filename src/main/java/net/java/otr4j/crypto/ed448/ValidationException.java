/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import javax.annotation.Nonnull;

/**
 * ValidationException indicates an issue while performing Ed448 elliptic curve operations.
 * <p>
 * Typically these exceptions indicate either issues with the public key (e.g. an illegal point) or a problem with
 * validating a message against its supposed signature.
 */
public final class ValidationException extends Exception {

    private static final long serialVersionUID = 8773101647127876355L;

    ValidationException(@Nonnull final String message) {
        super(message);
    }

    ValidationException(@Nonnull final String message, @Nonnull final Throwable cause) {
        super(message, cause);
    }
}
