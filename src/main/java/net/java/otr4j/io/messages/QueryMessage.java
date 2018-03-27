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
 * OTRv2 OTR query message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public class QueryMessage implements Message {

    public final Set<Integer> versions;

    public QueryMessage(@Nonnull final Set<Integer> versions) {
        this.versions = Objects.requireNonNull(versions);
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 47 * hash + Objects.hashCode(this.versions);
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
        final QueryMessage other = (QueryMessage) obj;
        if (!Objects.equals(this.versions, other.versions)) {
            return false;
        }
        return true;
    }
}
