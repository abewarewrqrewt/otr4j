/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import javax.annotation.Nonnull;

/**
 * Exception indicating some unsupported type is encountered and we cannot
 * successfully read the corresponding data.
 */
public final class UnsupportedTypeException extends Exception {

    private static final long serialVersionUID = -886137273673617736L;

    UnsupportedTypeException(@Nonnull final String message) {
        super(message);
    }
}
