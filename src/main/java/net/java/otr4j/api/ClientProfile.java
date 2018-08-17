package net.java.otr4j.api;

import net.java.otr4j.api.Session.OTRv;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;
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
     * List of supported versions.
     */
    private final Set<Integer> versions;

    /**
     * Profile expiration date in 64-bit Unix timestamp (ignoring leap seconds).
     */
    private final long expirationUnixTime;

    /**
     * DSA public key.
     */
    private final DSAPublicKey dsaPublicKey;

    /**
     * Constructor for the client profile instance.
     *
     * @param instanceTag        the instance tag
     * @param longTermPublicKey  the long-term Ed448 public key
     * @param versions           supported protocol versions
     * @param expirationUnixTime the expiration date in unix timestamp (in seconds)
     * @param dsaPublicKey       the DSA public key
     */
    public ClientProfile(@Nonnull final InstanceTag instanceTag, @Nonnull final Point longTermPublicKey,
            @Nonnull final Set<Integer> versions, final long expirationUnixTime,
            @Nullable final DSAPublicKey dsaPublicKey) {
        this.instanceTag = requireNonNull(instanceTag);
        this.longTermPublicKey = requireNonNull(longTermPublicKey);
        this.versions = requireMinElements(1, requireElements(singletonList(OTRv.FOUR),
            requireNoIllegalValues(asList(OTRv.ONE, OTRv.TWO), versions)));
        this.expirationUnixTime = expirationUnixTime;
        this.dsaPublicKey = dsaPublicKey;
    }

    /**
     * Get the instance tag.
     *
     * @return Returns the instance tag.
     */
    @Nonnull
    public InstanceTag getInstanceTag() {
        return instanceTag;
    }

    /**
     * Get the long-term Ed448 public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getLongTermPublicKey() {
        return longTermPublicKey;
    }

    /**
     * Get the supported OTR protocol versions.
     *
     * @return Returns the versions.
     */
    @Nonnull
    public Set<Integer> getVersions() {
        return versions;
    }

    /**
     * Get the expiration date as unix timestamp (in seconds).
     *
     * @return Returns the unix timestamp in seconds.
     */
    public long getExpirationUnixTime() {
        return expirationUnixTime;
    }

    /**
     * The long-term DSA public key. (Used in OTRv3.)
     *
     * @return Returns the public key.
     */
    @Nullable
    public DSAPublicKey getDsaPublicKey() {
        return dsaPublicKey;
    }
}
