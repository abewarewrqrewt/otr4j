/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;
import java.util.Objects;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Collections.requireElements;
import static net.java.otr4j.util.Collections.requireMinElements;
import static net.java.otr4j.util.Collections.requireNoIllegalValues;

/**
 * The validated representation of the ClientProfile.
 */
// TODO provide utility methods to simplify generating a new client profile as much as possible. The code for using OTRv4 should become as simple and as straight-forward as possible.
public final class ClientProfile {

    /**
     * Owner's instance tag.
     */
    private final InstanceTag instanceTag;

    /**
     * Public key of the long-term Ed448 keypair.
     */
    private final Point longTermPublicKey;

    /**
     * Public key of the Ed448 Forging key.
     */
    private final Point forgingKey;

    /**
     * List of supported versions.
     */
    private final Set<Integer> versions;

    /**
     * DSA public key.
     */
    private final DSAPublicKey dsaPublicKey;

    /**
     * Constructor for the client profile instance.
     *
     * @param instanceTag        the instance tag
     * @param longTermPublicKey  the long-term Ed448 public key
     * @param forgingKey         the Ed448 Forging public key
     * @param versions           supported protocol versions
     * @param dsaPublicKey       the DSA public key
     */
    public ClientProfile(@Nonnull final InstanceTag instanceTag, @Nonnull final Point longTermPublicKey,
            @Nonnull final Point forgingKey, @Nonnull final Set<Integer> versions,
            @Nullable final DSAPublicKey dsaPublicKey) {
        this.instanceTag = requireNonNull(instanceTag);
        this.longTermPublicKey = requireNonNull(longTermPublicKey);
        this.forgingKey = requireNonNull(forgingKey);
        this.versions = requireMinElements(1, requireElements(singletonList(OTRv.FOUR),
                requireNoIllegalValues(asList(OTRv.ONE, OTRv.TWO), versions)));
        this.dsaPublicKey = dsaPublicKey;
    }

    /**
     * Get the instance tag.
     *
     * @return Returns the instance tag.
     */
    @Nonnull
    public InstanceTag getInstanceTag() {
        return this.instanceTag;
    }

    /**
     * Get the long-term Ed448 public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getLongTermPublicKey() {
        return this.longTermPublicKey;
    }

    /**
     * Get the Forging public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getForgingKey() {
        return this.forgingKey;
    }

    /**
     * Get the supported OTR protocol versions.
     *
     * @return Returns the versions.
     */
    @Nonnull
    public Set<Integer> getVersions() {
        return this.versions;
    }

    /**
     * The long-term DSA public key. (Used in OTRv3.)
     *
     * @return Returns the public key.
     */
    @Nullable
    public DSAPublicKey getDsaPublicKey() {
        return this.dsaPublicKey;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ClientProfile that = (ClientProfile) o;
        return Objects.equals(instanceTag, that.instanceTag)
                && Objects.equals(longTermPublicKey, that.longTermPublicKey)
                && Objects.equals(forgingKey, that.forgingKey) && Objects.equals(versions, that.versions)
                && Objects.equals(dsaPublicKey, that.dsaPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(instanceTag, longTermPublicKey, forgingKey, versions, dsaPublicKey);
    }
}
