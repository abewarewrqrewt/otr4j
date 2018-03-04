/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

import java.util.Objects;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * 
 * @author George Politis
 * @author Danny van Heumen
 */
public final class PlainTextMessage extends QueryMessage {

    private static final int MESSAGE_PLAINTEXT = 0x102;

    public final String cleanText;

    public PlainTextMessage(@Nonnull final Set<Integer> versions,
            @Nonnull final String cleanText) {
        super(versions);
        this.cleanText = Objects.requireNonNull(cleanText);
    }

    @Override
    public int getType() {
        return MESSAGE_PLAINTEXT;
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
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        PlainTextMessage other = (PlainTextMessage) obj;
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
