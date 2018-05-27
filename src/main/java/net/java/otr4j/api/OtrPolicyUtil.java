/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import java.util.HashSet;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Utilities for OtrPolicy.
 *
 * @author Danny van Heumen
 */
public final class OtrPolicyUtil {

    private OtrPolicyUtil() {
        // utility class, should not be instantiated
    }

    /**
     * Determine list of allowed OTR versions based on the provided OTR policy.
     *
     * @param policy The active OTR policy.
     * @return Returns list of allowed OTR versions.
     */
    @Nonnull
    public static Set<Integer> allowedVersions(@Nonnull final OtrPolicy policy) {
        final HashSet<Integer> versions = new HashSet<>();
        if (policy.getAllowV2()) {
            versions.add(Session.OTRv.TWO);
        }
        if (policy.getAllowV3()) {
            versions.add(Session.OTRv.THREE);
        }
        if (policy.getAllowV4()) {
            versions.add(Session.OTRv.FOUR);
        }
        return versions;
    }
}
