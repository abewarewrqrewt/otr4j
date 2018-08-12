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

import static java.util.Objects.requireNonNull;

/**
 * OTRv2 OTR query message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// FIXME QueryMessage not constructed in way where tag is relevant for serialization. Consider restructuring this such that work is fully predictable.
public class QueryMessage implements Message {

    private final Set<Integer> versions;
    private final String tag;

    /**
     * Constructor for query message.
     *
     * @param versions the set of versions
     */
    public QueryMessage(@Nonnull final Set<Integer> versions) {
        this.versions = requireNonNull(versions);
        // FIXME !!! bad workaround because we generate the actually sent Query-string in SerializationUtils.toString(m)!
        final StringBuilder tag = new StringBuilder("?OTRv");
        for(final int version : versions) {
            tag.append(version);
        }
        tag.append('?');
        this.tag = tag.toString();
    }

    /**
     * Construct a query message instance.
     *
     * @param tag      The original tag of the query message in its original textual representation.
     * @param versions The versions included in the query message.
     */
    public QueryMessage(@Nonnull final String tag, @Nonnull final Set<Integer> versions) {
        this.tag = requireNonNull(tag);
        this.versions = requireNonNull(versions);
    }

    /**
     * Get the set of versions.
     *
     * @return Returns versions.
     */
    @Nonnull
    public Set<Integer> getVersions() {
        return versions;
    }

    /**
     * Get the query tag.
     *
     * @return Returns the query tag.
     */
    @Nonnull
    public String getTag() {
        return tag;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 47 * hash + Objects.hashCode(this.versions);
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
        final QueryMessage other = (QueryMessage) obj;
        return Objects.equals(this.versions, other.versions);
    }
}
