package net.java.otr4j.profile;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine;
import nl.dannyvanheumen.joldilocks.Ed448;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

import static net.java.otr4j.io.SerializationUtils.writeUserProfile;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * Utility class for user profiles.
 */
public final class UserProfiles {

    private UserProfiles() {
        // No need to instantiate utility class.
    }

    /**
     * Sign a user profile with OTRv4 EC signature and optionally with a transitional signature.
     *
     * @param profile The user profile.
     */
    public static void sign(@Nonnull final UserProfile profile, @Nonnull final PrivateKey dsaPrivateKey,
                            @Nonnull final BigInteger ecSecretKey) {
        final byte[] m = writeUserProfile(profile);
        final byte[] transitionalSignature = OtrCryptoEngine.sign(m, dsaPrivateKey);
        final byte[] userProfileSignature = Ed448.sign(ecSecretKey, new byte[0], concatenate(m, transitionalSignature));
        // FIXME continue implementation.
        throw new UnsupportedOperationException("To be implemented");
    }

    /**
     * Verify user profile.
     *
     * @param profile user profile to be verified.
     */
    public static void validate(@Nonnull final UserProfile profile) throws InvalidUserProfileException {
        // Verify that the User Profile has not expired.
        final Date now = new Date();
        final Date expirationDate = new Date(profile.getExpirationUnixTime());
        if (!now.before(expirationDate)) {
            throw new InvalidUserProfileException("User profile has expired.");
        }
        // Verify that the Versions field contains the character "4".
        if (!profile.getVersions().contains(Session.OTRv.FOUR)) {
            throw new InvalidUserProfileException("OTR version 4 is not included in list of acceptable user profiles.");
        }
        // Validate that the Public Shared Prekey and the Ed448 Public Key are on the curve Ed448-Goldilocks.
        if (!Ed448.contains(profile.getLongTermPublicKey())) {
            throw new InvalidUserProfileException("Illegal long-term public key included in the user profile.");
        }
        // If the Transitional Signature is present, verify its validity using the OTRv3 DSA key.
        // FIXME implement transition signature verification, if present.
        // Verify that the User Profile signature is valid.
        // FIXME Implement user profile signature validation.
        throw new UnsupportedOperationException("To be implemented.");
    }

    /**
     * Exception indicating an invalid user profile.
     */
    public static final class InvalidUserProfileException extends OtrException {

        private InvalidUserProfileException(@Nonnull final String message) {
            super(message);
        }
    }
}
