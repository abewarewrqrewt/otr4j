/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import javax.annotation.Nonnull;
import java.util.Objects;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * OTRv2 OTR query message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public class QueryMessage implements Message {

    private final Set<Integer> versions;

    /**
     * Constructor for query message.
     *
     * @param versions the set of versions
     */
    public QueryMessage(@Nonnull final Set<Integer> versions) {
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
