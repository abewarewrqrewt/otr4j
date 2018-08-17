/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AuthRMessage;
import net.java.otr4j.io.messages.ClientProfilePayload;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.IdentityMessage;
import net.java.otr4j.io.messages.ValidationException;
import net.java.otr4j.api.ClientProfile;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.io.messages.IdentityMessages.validate;
import static net.java.otr4j.io.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.io.messages.MysteriousT4.encode;

/**
 * Initial AKE state, a.k.a. NONE.
 * <p>
 * StateInitial can be initialized with a query tag in case such a tag was sent. Initially one would probably want to
 * use {@link #EMPTY} instance as no tag was sent yet.
 *
 * @author Danny van Heumen
 */
// FIXME migrate OTRv4 parts into Message State state machine.
public final class StateInitial extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateInitial.class.getName());

    /**
     * Instance with empty-string query tag, provided for convenience as any new AKE would start in this state.
     */
    private static final StateInitial EMPTY = new StateInitial("");

    private final String queryTag;

    /**
     * Constructor for initial state.
     *
     * @param queryTag the last query tag used
     */
    // FIXME we should ensure that everywhere a whitespace tag or query message is sent, we update the initial state to reflect the last such hint.
    public StateInitial(@Nonnull final String queryTag) {
        super();
        this.queryTag = requireNonNull(queryTag);
    }

    /**
     * Acquire the Singleton instance for StateInitial.
     *
     * @return Returns the singleton instance.
     */
    @Nonnull
    public static StateInitial empty() {
        return EMPTY;
    }

    @Nullable
    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message)
            throws OtrCryptoException, ValidationException {

        if (message.protocolVersion < Session.OTRv.TWO || message.protocolVersion > Session.OTRv.FOUR) {
            throw new IllegalArgumentException("unsupported protocol version");
        }
        if ((message.protocolVersion == Session.OTRv.TWO || message.protocolVersion == Session.OTRv.THREE)
                && message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (message.protocolVersion == Session.OTRv.FOUR && message instanceof IdentityMessage) {
            return handleIdentityMessage(context, (IdentityMessage) message);
        }
        // OTR: "Ignore the message."
        LOGGER.log(Level.INFO, "We only expect to receive a DH Commit message or an Identity message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
        return null;
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
        context.setState(new StateAwaitingRevealSig(message.protocolVersion, keypair, message.dhPublicKeyHash,
                message.dhPublicKeyEncrypted));
        LOGGER.finest("Sending D-H key message.");
        // OTR: "Sends Bob gy"
        return new DHKeyMessage(message.protocolVersion, (DHPublicKey) keypair.getPublic(),
                context.getSenderInstanceTag().getValue(), context.getReceiverInstanceTag().getValue());
    }

    // FIXME verify that message is correctly rejected + nothing responded when verification of IdentityMessage fails.
    @Nonnull
    private AuthRMessage handleIdentityMessage(@Nonnull final AuthContext context, @Nonnull final IdentityMessage message)
            throws OtrCryptoException, ValidationException {

        validate(message);
        final ClientProfile theirClientProfile = message.getClientProfile().validate();
        final ClientProfilePayload profile = context.getClientProfile();
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair x = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair a = DHKeyPair.generate(secureRandom);
        final EdDSAKeyPair longTermKeyPair = context.getLongTermKeyPair();
        // TODO should we verify that long-term key pair matches with long-term public key from user profile? (This would be an internal sanity check.)
        // Generate t value and calculate sigma based on known facts and generated t value.
        final byte[] t = encode(AUTH_R, profile, message.getClientProfile(), x.getPublicKey(), message.getY(),
            a.getPublicKey(), message.getB(), context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue(), this.queryTag, context.getLocalAccountID(),
            context.getRemoteAccountID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(secureRandom, longTermKeyPair,
                theirClientProfile.getLongTermPublicKey(), longTermKeyPair.getPublicKey(), message.getY(), t);
        // Generate response message and transition into next state.
        final AuthRMessage authRMessage = new AuthRMessage(Session.OTRv.FOUR, context.getSenderInstanceTag().getValue(),
                context.getReceiverInstanceTag().getValue(), context.getClientProfile(), x.getPublicKey(), a.getPublicKey(),
                sigma);
        context.setState(new StateAwaitingAuthI(this.queryTag, x, a, message.getY(), message.getB(), profile,
                message.getClientProfile()));
        return authRMessage;
    }
}
