package net.java.otr4j.profile;

import net.java.otr4j.api.Session;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Collections.requireMinElements;
import static net.java.otr4j.util.Collections.requireNoIllegalValues;

// FIXME Should we also allow versions 4 AND 3 when no transitional signature (OTRv3 long term public key) is provided?
// FIXME add support for multiple long-term keys with definite order. (Older keys before newer keys)
// FIXME update Client Profile composition as specification has changed.
public final class ClientProfile {

    /**
     * Owner's instance tag.
     */
    private final int instanceTag;

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

    public ClientProfile(final int instanceTag, @Nonnull final Point longTermPublicKey,
                         @Nonnull final Set<Integer> versions, final long expirationUnixTime) {
        this.instanceTag = instanceTag;
        this.longTermPublicKey = requireNonNull(longTermPublicKey);
        this.versions = requireMinElements(1, requireNoIllegalValues(versions, asList(Session.OTRv.ONE, Session.OTRv.TWO)));
        this.expirationUnixTime = expirationUnixTime;
    }

    public int getInstanceTag() {
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
}
