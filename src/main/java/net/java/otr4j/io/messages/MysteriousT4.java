package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrEncodables;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.io.SerializationUtils.generatePhi;
import static net.java.otr4j.io.SerializationUtils.writeMpi;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * Mysterious value t that is used in phi (shared session state) identification of OTRv4.
 */
public final class MysteriousT4 {

    private static final byte[] USAGE_ID_BOBS_PROFILE = new byte[]{0x06};

    private static final byte[] USAGE_ID_ALICES_PROFILE = new byte[]{0x07};

    private static final byte[] USAGE_ID_PHI_DERIVATIVE = new byte[]{0x08};

    private static final int USER_PROFILE_DERIVATIVE_LENGTH_BYTES = 64;

    private static final int PHI_DERIVATIVE_LENGTH_BYTES = 64;

    private MysteriousT4() {
        // For now this is a utility class. I'm not sure that this is the final incarnation, however for now, as T is
        // not a full message in itself, it doesn't make sense to implement the AbstractEncodedMessage interface for
        // encoding. For now this will suffice.
    }

    @Nonnull
    public static byte[] encode(@Nonnull final ClientProfilePayload profileAlice,
                                @Nonnull final ClientProfilePayload profileBob,
                                @Nonnull final Point x,
                                @Nonnull final Point y,
                                @Nonnull final BigInteger a,
                                @Nonnull final BigInteger b,
                                @Nonnull final int senderInstanceTag,
                                @Nonnull final int receiverInstanceTag,
                                @Nonnull final String queryTag,
                                @Nonnull final String senderContactID,
                                @Nonnull final String receiverContactID) {
        final byte[] bobsProfileEncoded = kdf1(concatenate(USAGE_ID_BOBS_PROFILE, OtrEncodables.encode(profileBob)),
            USER_PROFILE_DERIVATIVE_LENGTH_BYTES);
        final byte[] alicesProfileEncoded = kdf1(concatenate(USAGE_ID_ALICES_PROFILE, OtrEncodables.encode(profileAlice)),
            USER_PROFILE_DERIVATIVE_LENGTH_BYTES);
        final byte[] yEncoded = y.encode();
        final byte[] xEncoded = x.encode();
        final byte[] bEncoded = writeMpi(b);
        final byte[] aEncoded = writeMpi(a);
        final byte[] phi = generatePhi(senderInstanceTag, receiverInstanceTag, queryTag, senderContactID, receiverContactID);
        final byte[] sharedSessionDerivative = kdf1(concatenate(USAGE_ID_PHI_DERIVATIVE, phi),
            PHI_DERIVATIVE_LENGTH_BYTES);
        return concatenate(new byte[][]{new byte[]{0x00}, bobsProfileEncoded, alicesProfileEncoded, yEncoded, xEncoded,
            bEncoded, aEncoded, sharedSessionDerivative});
    }
}
