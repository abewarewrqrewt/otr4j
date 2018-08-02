package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage;
import net.java.otr4j.io.OtrEncodables;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * Mysterious value t that is used in phi (shared session state) identification of OTRv4.
 */
public final class MysteriousT4 {

    private static final int USER_PROFILE_DERIVATIVE_LENGTH_BYTES = 64;

    private static final int PHI_DERIVATIVE_LENGTH_BYTES = 64;

    public enum Purpose {
        AUTH_R, AUTH_I
    }

    private MysteriousT4() {
        // For now this is a utility class. I'm not sure that this is the final incarnation, however for now, as T is
        // not a full message in itself, it doesn't make sense to implement the AbstractEncodedMessage interface for
        // encoding. For now this will suffice.
    }

    @Nonnull
    public static byte[] encode(@Nonnull final Purpose purpose, @Nonnull final ClientProfilePayload profileAlice,
                                @Nonnull final ClientProfilePayload profileBob, @Nonnull final Point x,
                                @Nonnull final Point y, @Nonnull final BigInteger a, @Nonnull final BigInteger b,
                                final int senderInstanceTag, final int receiverInstanceTag,
                                @Nonnull final String queryTag, @Nonnull final String senderContactID,
                                @Nonnull final String receiverContactID) {
        final KDFUsage bobsProfileUsage;
        final KDFUsage alicesProfileUsage;
        final KDFUsage phiUsage;
        switch (purpose) {
            case AUTH_R:
                bobsProfileUsage = KDFUsage.AUTH_R_BOB_CLIENT_PROFILE;
                alicesProfileUsage = KDFUsage.AUTH_R_ALICE_CLIENT_PROFILE;
                phiUsage = KDFUsage.AUTH_R_PHI;
                break;
            case AUTH_I:
                bobsProfileUsage = KDFUsage.AUTH_I_BOB_CLIENT_PROFILE;
                alicesProfileUsage = KDFUsage.AUTH_I_ALICE_CLIENT_PROFILE;
                phiUsage = KDFUsage.AUTH_I_PHI;
                break;
            default:
                throw new UnsupportedOperationException("Unsupported purpose.");
        }
        final byte[] bobsProfileEncoded = kdf1(bobsProfileUsage, OtrEncodables.encode(profileBob),
            USER_PROFILE_DERIVATIVE_LENGTH_BYTES);
        final byte[] alicesProfileEncoded = kdf1(alicesProfileUsage, OtrEncodables.encode(profileAlice),
            USER_PROFILE_DERIVATIVE_LENGTH_BYTES);
        final byte[] yEncoded = y.encode();
        final byte[] xEncoded = x.encode();
        final byte[] bEncoded;
        try (OtrOutputStream out = new OtrOutputStream()) {
            out.writeBigInt(b);
            bEncoded = out.toByteArray();
        }
        final byte[] aEncoded;
        try (OtrOutputStream out = new OtrOutputStream()) {
            out.writeBigInt(a);
            aEncoded = out.toByteArray();
        }
        // FIXME double-check if phi is now a mix of phi and phi' values.
        final byte[] phi = generatePhi(senderInstanceTag, receiverInstanceTag, queryTag, senderContactID, receiverContactID);
        final byte[] sharedSessionDerivative = kdf1(phiUsage, phi, PHI_DERIVATIVE_LENGTH_BYTES);
        return concatenate(new byte[][]{new byte[]{0x00}, bobsProfileEncoded, alicesProfileEncoded, yEncoded, xEncoded,
            bEncoded, aEncoded, sharedSessionDerivative});
    }

    /**
     * Generate the shared session state that is used in verification the session consistency. Note that this part is
     * basically only concerned with the correct serialization of provided data.
     *
     * @param senderInstanceTag   The sender instance tag.
     * @param receiverInstanceTag The receiver instance tag.
     * @param queryTag            The query message.
     * @param senderContactID     The sender's contact ID (i.e. the infrastructure's identifier such as XMPP's bare JID.)
     * @param receiverContactID   The receiver's contact ID (i.e. the infrastructure's identifier such as XMPP's bare JID.)
     * @return Returns generate Phi value.
     */
    // TODO generatePhi is package-private only for purpose of testing. Consider if we want to make this private and test only through MysteriousT4-encoding.
    @Nonnull
    static byte[] generatePhi(final int senderInstanceTag, final int receiverInstanceTag, @Nonnull final String queryTag,
                              @Nonnull final String senderContactID, @Nonnull final String receiverContactID) {
        final byte[] queryTagBytes = queryTag.getBytes(US_ASCII);
        final byte[] senderIDBytes = senderContactID.getBytes(UTF_8);
        final byte[] receiverIDBytes = receiverContactID.getBytes(UTF_8);
        try (OtrOutputStream out = new OtrOutputStream()) {
            out.writeInt(senderInstanceTag);
            out.writeInt(receiverInstanceTag);
            out.writeData(queryTagBytes);
            out.writeData(senderIDBytes);
            out.writeData(receiverIDBytes);
            return out.toByteArray();
        }
    }
}
