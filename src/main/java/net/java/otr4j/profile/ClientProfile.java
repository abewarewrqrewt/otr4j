package net.java.otr4j.profile;

import net.java.otr4j.api.InstanceTag;
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

// FIXME add support for multiple long-term keys with definite order. (Older keys before newer keys)
// FIXME update Client Profile composition as specification has changed.
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

    public ClientProfile(@Nonnull final InstanceTag instanceTag, @Nonnull final Point longTermPublicKey,
                         @Nonnull final Set<Integer> versions, final long expirationUnixTime,
                         @Nullable DSAPublicKey dsaPublicKey) {
        this.instanceTag = requireNonNull(instanceTag);
        this.longTermPublicKey = requireNonNull(longTermPublicKey);
        this.versions = requireMinElements(1, requireElements(singletonList(OTRv.FOUR),
            requireNoIllegalValues(asList(OTRv.ONE, OTRv.TWO), versions)));
        this.expirationUnixTime = expirationUnixTime;
        this.dsaPublicKey = dsaPublicKey;
    }

    @Nonnull
    public InstanceTag getInstanceTag() {
        return instanceTag;
    }

    @Nonnull
    public Point getLongTermPublicKey() {
        return longTermPublicKey;
    }

    @Nonnull
    public Set<Integer> getVersions() {
        return versions;
    }

    public long getExpirationUnixTime() {
        return expirationUnixTime;
    }

    @Nullable
    public DSAPublicKey getDsaPublicKey() {
        return dsaPublicKey;
    }
}
