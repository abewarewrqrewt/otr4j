package net.java.otr4j.profile;

import net.java.otr4j.api.Session;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Collections.requireNoIllegalValues;

// FIXME implement User Profile
// TODO Ensure that shared pre-key expires at same time as user profile.
// FIXME Should we also allow versions 4 AND 3 when no transitional signature (OTRv3 long term public key) is provided?
public final class UserProfile {

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
     * Public shared pre-key.
     */
    private final Point publicSharedPrekey;

    /**
     * Signature using OTRv3 long-term key.
     */
    private final byte[] transitionalSignature;

    /**
     * Signature using OTRv4 long-term Ed448 public key.
     */
    private final byte[] profileSignature;

    public UserProfile(@Nonnull final Point longTermPublicKey, @Nonnull final Collection<Integer> versions,
                       final long expirationUnixTime, @Nonnull final Point publicSharedPrekey,
                       @Nonnull final byte[] profileSignature, @Nullable final byte[] transitionalSignature) {
        this.longTermPublicKey = requireNonNull(longTermPublicKey);
        this.versions = requireNoIllegalValues(versions, Session.OTRv.ONE, Session.OTRv.TWO);
        this.expirationUnixTime = expirationUnixTime;
        this.publicSharedPrekey = requireNonNull(publicSharedPrekey);
        this.transitionalSignature = transitionalSignature;
        this.profileSignature = requireNonNull(profileSignature);
    }
}
