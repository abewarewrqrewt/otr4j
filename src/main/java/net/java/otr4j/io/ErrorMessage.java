/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import java.util.Objects;
import javax.annotation.Nonnull;

/**
 * OTRv2 OTR error message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class ErrorMessage implements Message {

    /**
     * The error message.
     */
    public final String error;

    /**
     * Constructor for error message.
     *
     * @param error the error message itself
     */
    public ErrorMessage(@Nonnull final String error) {
        this.error = Objects.requireNonNull(error);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + Objects.hashCode(this.error);
        return hash;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ErrorMessage other = (ErrorMessage) obj;
        return Objects.equals(this.error, other.error);
    }
}
