/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import net.java.otr4j.api.Session.Version;

import javax.annotation.Nonnull;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * The plain text message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class PlainTextMessage extends QueryMessage {

    @Nonnull
    private final String cleanText;

    /**
     * Constructor for plaintext message.
     *
     * @param tag       the whitespace tag
     * @param versions  the protocol versions
     * @param cleanText the plain text message content
     */
    public PlainTextMessage(@Nonnull final String tag, @Nonnull final Set<Integer> versions,
            @Nonnull final String cleanText) {
        super(tag, versions);
        this.cleanText = requireNonNull(cleanText);
    }

    /**
     * Construct new PlainTextMessage instance using set of versions as source to determine the whitespace tag.
     *
     * @param versions  the allowed OTR protocol versions
     * @param cleanText the plain-text message
     */
    public PlainTextMessage(@Nonnull final Set<Integer> versions, @Nonnull final String cleanText) {
        super(versions.isEmpty() ? "" : generateWhitespaceTag(versions), versions);
        this.cleanText = requireNonNull(cleanText);
    }

    @Nonnull
    private static String generateWhitespaceTag(@Nonnull final Iterable<Integer> versions) {
        final StringBuilder builder = new StringBuilder(58);
        builder.append(" \t  \t\t\t\t \t \t \t  ");
        for (final int version : versions) {
            if (version == Version.TWO) {
                builder.append("  \t\t  \t ");
            }
            if (version == Version.THREE) {
                builder.append("  \t\t  \t\t");
            }
            if (version == Version.FOUR) {
                builder.append("  \t\t \t  ");
            }
        }
        return builder.toString();
    }

    /**
     * The clean text, i.e. the plain text without possible embedded whitespace tag.
     *
     * @return Returns text.
     */
    @Nonnull
    public String getCleanText() {
        return cleanText;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + cleanText.hashCode();
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
        return cleanText.equals(other.cleanText);
    }
}
