package net.java.otr4j.profile;

import net.java.otr4j.api.Session;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.util.Collection;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.ByteArrays.requireZeroOrLengthExactly;
import static net.java.otr4j.util.Collections.requireNoIllegalValues;

// FIXME Should we also allow versions 4 AND 3 when no transitional signature (OTRv3 long term public key) is provided?
// FIXME add support for multiple long-term keys with definite order. (Older keys before newer keys)
// FIXME update Client Profile composition as specification has changed.
public final class ClientProfile {

    private static final int EDDSA_SIGNATURE_LENGTH_BYTES = 114;
    private static final int DSA_SIGNATURE_LENGTH_BYTES = 20;

    /**
     * User Profile's identifier.
     */
    private final int identifier;

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
    private final Collection<Integer> versions;

    /**
     * Profile expiration date in 64-bit Unix timestamp (ignoring leap seconds).
     */
    private final long expirationUnixTime;

    /**
     * Signature using OTRv3 long-term key.
     */
    private final byte[] transitionalSignature;

    /**
     * Signature using OTRv4 long-term Ed448 public key.
     */
    private final byte[] profileSignature;

    public ClientProfile(final int identifier, final int instanceTag, @Nonnull final Point longTermPublicKey,
                         @Nonnull final Collection<Integer> versions, final long expirationUnixTime,
                         @Nonnull final byte[] transitionalSignature, @Nonnull final byte[] profileSignature) {
        this.identifier = identifier;
        this.instanceTag = instanceTag;
        this.longTermPublicKey = requireNonNull(longTermPublicKey);
        this.versions = requireNoIllegalValues(versions, Session.OTRv.ONE, Session.OTRv.TWO);
        this.expirationUnixTime = expirationUnixTime;
        this.transitionalSignature = requireZeroOrLengthExactly(DSA_SIGNATURE_LENGTH_BYTES, transitionalSignature);
        this.profileSignature = requireLengthExactly(EDDSA_SIGNATURE_LENGTH_BYTES, profileSignature);
    }

    public int getIdentifier() {
        return identifier;
    }

    public int getInstanceTag() {
        return instanceTag;
    }

    @Nonnull
    public Point getLongTermPublicKey() {
        return longTermPublicKey;
    }

    @Nonnull
    public Collection<Integer> getVersions() {
        return versions;
    }

    public long getExpirationUnixTime() {
        return expirationUnixTime;
    }

    @Nonnull
    public byte[] getTransitionalSignature() {
        return transitionalSignature;
    }

    @Nonnull
    public byte[] getProfileSignature() {
        return profileSignature;
    }
}
