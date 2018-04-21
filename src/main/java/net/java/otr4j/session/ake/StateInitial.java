/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AuthRMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.IdentityMessage;
import net.java.otr4j.profile.UserProfile;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.io.SerializationUtils.generatePhi;
import static net.java.otr4j.io.SerializationUtils.writeMpi;
import static net.java.otr4j.io.SerializationUtils.writeUserProfile;
import static net.java.otr4j.io.messages.IdentityMessages.verify;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * Initial AKE state, a.k.a. NONE. (Singleton)
 *
 * @author Danny van Heumen
 */
public final class StateInitial extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateInitial.class.getName());

    private static final byte[] USAGE_ID_BOBS_PROFILE = new byte[]{0x06};

    private static final byte[] USAGE_ID_ALICES_PROFILE = new byte[]{0x07};

    private static final byte[] USAGE_ID_PHI_DERIVATIVE = new byte[]{0x08};

    private static final int USER_PROFILE_DERIVATIVE_LENGTH_BYTES = 64;

    private static final int PHI_DERIVATIVE_LENGTH_BYTES = 64;

    /**
     * Singleton instance.
     */
    private static final StateInitial INSTANCE = new StateInitial();

    private StateInitial() {
        // Singleton, we only need to instantiate a single instance that can
        // then be reused in all sessions. Given that this is the initial state
        // we have no state on an AKE negotiation yet.
    }

    /**
     * Acquire the Singleton instance for StateInitial.
     *
     * @return Returns the singleton instance.
     */
    @Nonnull
    public static StateInitial instance() {
        return INSTANCE;
    }

    @Nullable
    @Override
    public DHKeyMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) {
        if (!(message instanceof DHCommitMessage)) {
            // OTR: "Ignore the message."
            LOGGER.log(Level.INFO, "We only expect to receive a DH Commit message. Ignoring message with messagetype: {0}", message.getType());
            return null;
        }
        if (message.protocolVersion < 2 || message.protocolVersion > 3) {
            throw new IllegalArgumentException("unsupported protocol version");
        }
        return handleDHCommitMessage(context, (DHCommitMessage) message);
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Nonnull
    private DHKeyMessage handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) {
        // OTR: "Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG."
        // OTR: "Choose a random value y (at least 320 bits), and calculate gy."
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        context.setState(new StateAwaitingRevealSig(message.protocolVersion,
                keypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
        LOGGER.finest("Sending D-H key message.");
        // OTR: "Sends Bob gy"
        return new DHKeyMessage(message.protocolVersion, (DHPublicKey) keypair.getPublic(),
                context.getSenderInstanceTag().getValue(), context.getReceiverInstanceTag().getValue());
    }

    // FIXME verify that message is correctly rejected + nothing responded when verification of IdentityMessage fails.
    @Nonnull
    private AuthRMessage handleIdentityMessage(@Nonnull final AuthContext context,
                                               @Nonnull final IdentityMessage message) throws OtrException {
        verify(message);
        final UserProfile profile = context.getUserProfile();
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair x = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair a = DHKeyPair.generate(secureRandom);
        final byte[] t;
        {
            final byte[] bobsProfileEncoded = kdf1(concatenate(USAGE_ID_BOBS_PROFILE,
                writeUserProfile(message.getUserProfile())), USER_PROFILE_DERIVATIVE_LENGTH_BYTES);
            final byte[] alicesProfileEncoded = kdf1(concatenate(USAGE_ID_ALICES_PROFILE, writeUserProfile(profile)),
                USER_PROFILE_DERIVATIVE_LENGTH_BYTES);
            final byte[] yEncoded = message.getY().encode();
            final byte[] xEncoded = x.getPublicKey().encode();
            final byte[] bEncoded = writeMpi(message.getB());
            final byte[] aEncoded = writeMpi(a.getPublicKey());
            // FIXME need to acquire query string, contact IDs.
            final String queryString;
            final String senderContactID;
            final String receiverContactID;
            final byte[] phi = generatePhi(context.getSenderInstanceTag().getValue(),
                context.getReceiverInstanceTag().getValue(), queryString, senderContactID, receiverContactID);
            final byte[] sharedSessionDerivative = kdf1(concatenate(USAGE_ID_PHI_DERIVATIVE, phi),
                PHI_DERIVATIVE_LENGTH_BYTES);
            t = concatenate(new byte[][]{new byte[]{0x00}, bobsProfileEncoded, alicesProfileEncoded, yEncoded, xEncoded,
                bEncoded, aEncoded, sharedSessionDerivative});
        }
        // FIXME we cannot yet set the exact order of public keys: H_b, H_a, Y
        final OtrCryptoEngine4.Sigma sigma = ringSign(secureRandom, x, message.getUserProfile().getLongTermPublicKey(),
            message.getY(), t);
        final AuthRMessage authRMessage = new AuthRMessage(Session.OTRv.FOUR, context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue(), context.getUserProfile(), x.getPublicKey(), a.getPublicKey(),
            sigma);
        context.setState(new StateAwaitingAuthI(x, a));
        return authRMessage;
    }
}
