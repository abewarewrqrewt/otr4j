/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import javax.annotation.Nonnull;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * 
 * @author George Politis
 * @author Danny van Heumen
 */
public final class PlainTextMessage extends QueryMessage {

    private final String cleanText;

    public PlainTextMessage(@Nonnull final String tag, @Nonnull final Set<Integer> versions,
            @Nonnull final String cleanText) {
        super(tag, versions);
        this.cleanText = requireNonNull(cleanText);
    }

    @Nonnull
    public String getCleanText() {
        return cleanText;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result
                + ((cleanText == null) ? 0 : cleanText.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PlainTextMessage other = (PlainTextMessage) obj;
        if (cleanText == null) {
            if (other.cleanText != null) {
                return false;
            }
        } else if (!cleanText.equals(other.cleanText)) {
            return false;
        }
        return true;
    }
}
