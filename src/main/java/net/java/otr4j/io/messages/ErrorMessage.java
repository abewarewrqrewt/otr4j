/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import java.util.Objects;
import javax.annotation.Nonnull;

/**
 * OTRv2 OTR error message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class ErrorMessage implements Message {

    public final String error;

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
    public boolean equals(Object obj) {
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
        if (!Objects.equals(this.error, other.error)) {
            return false;
        }
        return true;
    }
}
