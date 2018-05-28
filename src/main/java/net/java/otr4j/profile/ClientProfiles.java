package net.java.otr4j.profile;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Set;

import static net.java.otr4j.crypto.OtrCryptoEngine4.verifyEdDSAPublicKey;
import static net.java.otr4j.io.SerializationUtils.ASCII;
import static net.java.otr4j.io.SerializationUtils.encodeVersionString;
import static net.java.otr4j.io.SerializationUtils.parseVersionString;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * Utility class for user profiles.
 */
public final class ClientProfiles {

    private static final byte[] ED448_CONTEXT = new byte[0];

    private ClientProfiles() {
        // No need to instantiate utility class.
    }

    /**
     * Sign a user profile with OTRv4 EC signature and optionally with a transitional signature.
     *
     * @param profile The user profile.
     */
    public static void sign(@Nonnull final ClientProfile profile, @Nonnull final PrivateKey dsaPrivateKey,
                            @Nonnull final BigInteger ecSecretKey) {
        final byte[] m = write(profile);
        final byte[] transitionalSignature = OtrCryptoEngine.sign(m, dsaPrivateKey);
        final byte[] clientProfileSignature = Ed448.sign(ecSecretKey, ED448_CONTEXT, concatenate(m, transitionalSignature));
        // FIXME continue implementation.
        throw new UnsupportedOperationException("To be implemented");
    }

    /**
     * Verify user profile.
     *
     * @param profile user profile to be verified.
     */
    public static void validate(@Nonnull final ClientProfile profile) throws InvalidClientProfileException,
        OtrCryptoException {

        // Verify that the User Profile has not expired.
        final Date now = new Date();
        final Date expirationDate = new Date(profile.getExpirationUnixTime());
        if (!now.before(expirationDate)) {
            throw new InvalidClientProfileException("User profile has expired.");
        }
        // Verify that the Versions field contains the character "4".
        if (!profile.getVersions().contains(Session.OTRv.FOUR)) {
            throw new InvalidClientProfileException("OTR version 4 is not included in user profile list of accepted OTR protocol versions.");
        }
        // Validate that the Public Shared Prekey and the Ed448 Public Key are on the curve Ed448-Goldilocks.
        verifyEdDSAPublicKey(profile.getLongTermPublicKey());
        // If the Transitional Signature is present, verify its validity using the OTRv3 DSA key.
        // FIXME implement transition signature verification, if present.
        // Verify that the User Profile signature is valid.
        // FIXME Implement user profile signature validation.
        throw new UnsupportedOperationException("To be implemented.");
    }

    /**
     * Read ClientProfile from provided input stream.
     *
     * @param in The input stream
     * @return Returns ClientProfile reconstructed from data on input stream.
     * @throws IOException        In case of failure to read from stream.
     * @throws OtrCryptoException In case of illegal data encountered while reconstructing ClientProfile.
     */
    @Nonnull
    public static ClientProfile readFrom(@Nonnull final OtrInputStream in) throws IOException, OtrCryptoException {
        final int identifier = in.readInt();
        final int instanceTag = in.readInt();
        final Point longTermPublicKey = in.readPoint();
        final Set<Integer> versions = parseVersionString(new String(in.readData(), ASCII));
        final long expirationUnixTime = in.readLong();
        final byte[] transitionalSignature = in.readData();
        final byte[] profileSignature = in.readData();
        return new ClientProfile(identifier, instanceTag, longTermPublicKey, versions, expirationUnixTime,
            transitionalSignature, profileSignature);
    }

    @Nonnull
    public static byte[] write(@Nonnull final ClientProfile profile) {
        try (final OtrOutputStream out = new OtrOutputStream()) {
            writeTo(out, profile);
            return out.toByteArray();
        }
    }

    /**
     * Write ClientProfile to provided output stream.
     *
     * @param profile The client profile
     * @param out     The OTR output stream
     */
    public static void writeTo(@Nonnull final OtrOutputStream out, @Nonnull final ClientProfile profile) {
        out.writeInt(profile.getIdentifier());
        out.writeInt(profile.getInstanceTag());
        out.writePoint(profile.getLongTermPublicKey());
        out.writeData(encodeVersionString(profile.getVersions()).getBytes(ASCII));
        out.writeLong(profile.getExpirationUnixTime());
        out.writeData(profile.getTransitionalSignature());
        out.writeData(profile.getProfileSignature());
    }

    /**
     * Exception indicating an invalid user profile.
     */
    public static final class InvalidClientProfileException extends OtrException {

        private InvalidClientProfileException(@Nonnull final String message) {
            super(message);
        }
    }
}
