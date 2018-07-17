/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.UnsupportedTypeException;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureM;
import net.java.otr4j.io.messages.SignatureMessage;
import net.java.otr4j.io.messages.SignatureX;

import static net.java.otr4j.io.OtrEncodables.encode;

/**
 * AKE state Awaiting Signature message, a.k.a. AUTHSTATE_AWAITING_SIG.
 *
 * @author Danny van Heumen
 */
final class StateAwaitingSig extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingSig.class.getName());

    private final int version;
    private final KeyPair localDHKeyPair;
    private final DHPublicKey remoteDHPublicKey;
    private final SharedSecret s;

    /**
     * Saved copy of the Reveal Signature Message for retransmission in case we
     * receive a DH Key message with the exact same DH public key.
     */
    private final RevealSignatureMessage previousRevealSigMessage;

    StateAwaitingSig(final int version,
            @Nonnull final KeyPair localDHKeyPair,
            @Nonnull final DHPublicKey remoteDHPublicKey,
            @Nonnull final SharedSecret s,
            @Nonnull final RevealSignatureMessage previousRevealSigMessage) {
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unsupported version specified");
        }
        this.version = version;
        this.localDHKeyPair = Objects.requireNonNull(localDHKeyPair);
        try {
            this.remoteDHPublicKey = OtrCryptoEngine.verify(remoteDHPublicKey);
        } catch (final OtrCryptoException ex) {
            throw new IllegalArgumentException("Illegal D-H Public Key provided.", ex);
        }
        this.s = Objects.requireNonNull(s);
        this.previousRevealSigMessage = Objects.requireNonNull(previousRevealSigMessage);
    }

    @Nullable
    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message)
        throws OtrException, AuthContext.InteractionFailedException, IOException {

        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (message.protocolVersion != this.version) {
            throw new IllegalArgumentException("unexpected version");
        }
        if (message instanceof DHKeyMessage) {
            return handleDHKeyMessage((DHKeyMessage) message);
        } else if (message instanceof SignatureMessage) {
            try {
                return handleSignatureMessage(context, (SignatureMessage) message);
            } catch (final UnsupportedTypeException e) {
                throw new OtrException("Unsupported type of signature encountered.", e);
            }
        } else {
            LOGGER.log(Level.FINEST, "Only expected message types are DHKeyMessage and SignatureMessage. Ignoring message with type: {0}", message.getType());
            return null;
        }
    }

    @Override
    public int getVersion() {
        return this.version;
    }

    @Nonnull
    private DHKeyMessage handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) {
        // OTR: "Reply with a new D-H Key message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG."
        LOGGER.finest("Generating local D-H key pair.");
        // OTR: "Choose a random value y (at least 320 bits), and calculate gy."
        final KeyPair newKeypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Ignoring AWAITING_SIG state and sending a new DH key message.");
        context.setState(new StateAwaitingRevealSig(message.protocolVersion, newKeypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
        return new DHKeyMessage(message.protocolVersion, (DHPublicKey) newKeypair.getPublic(),
                context.getSenderInstanceTag().getValue(), context.getReceiverInstanceTag().getValue());
    }

    @Nullable
    private RevealSignatureMessage handleDHKeyMessage(@Nonnull final DHKeyMessage message) {
        // OTR: "If this D-H Key message is the same the one you received earlier (when you entered AUTHSTATE_AWAITING_SIG):
        // Retransmit your Reveal Signature Message. Otherwise: Ignore the message."
        if (!((DHPublicKey) this.localDHKeyPair.getPublic()).getY().equals(message.dhPublicKey.getY())) {
            // DH keypair is not the same as local pair, this message is either
            // fake or not intended for this session.
            LOGGER.info("DHKeyMessage contains different DH public key. Ignoring message.");
            return null;
        }
        // DH keypair is the same, so other side apparently didn't receive our
        // first reveal signature message, let's send the message again.
        return this.previousRevealSigMessage;
    }

    @Nullable
    private SignatureMessage handleSignatureMessage(@Nonnull final AuthContext context, @Nonnull final SignatureMessage message)
            throws OtrCryptoException, AuthContext.InteractionFailedException, IOException, UnsupportedTypeException {
        // OTR: "Decrypt the encrypted signature, and verify the signature and the MACs."
        try {
            // OTR: "Uses m2' to verify MACm2'(AESc'(XA))"
            final byte[] xEncryptedBytes = SerializationUtils.writeData(message.xEncrypted);
            final byte[] xEncryptedMAC = OtrCryptoEngine.sha256Hmac160(xEncryptedBytes, s.m2p());
            OtrCryptoEngine.checkEquals(xEncryptedMAC, message.xEncryptedMAC, "xEncryptedMAC failed verification.");
            // OTR: "Uses c' to decrypt AESc'(XA) to obtain XA = pubA, keyidA, sigA(MA)"
            final byte[] remoteXBytes = OtrCryptoEngine.aesDecrypt(s.cp(), null, message.xEncrypted);
            final SignatureX remoteX = SerializationUtils.toMysteriousX(remoteXBytes);
            // OTR: "Computes MA = MACm1'(gy, gx, pubA, keyidA)"
            final SignatureM remoteM = new SignatureM(this.remoteDHPublicKey,
                    (DHPublicKey) this.localDHKeyPair.getPublic(),
                    remoteX.longTermPublicKey, remoteX.dhKeyID);
            final byte[] expectedSignature = OtrCryptoEngine.sha256Hmac(encode(remoteM), s.m1p());
            // OTR: "Uses pubA to verify sigA(MA)"
            OtrCryptoEngine.verify(expectedSignature, remoteX.longTermPublicKey, remoteX.signature);
            // Transition to ENCRYPTED session state.
            // OTR: "Transition msgstate to MSGSTATE_ENCRYPTED."
            final SecurityParameters params = new SecurityParameters(this.version,
                    this.localDHKeyPair, remoteX.longTermPublicKey,
                    remoteDHPublicKey, this.s);
            context.secure(params);
            return null;
        } finally {
            // Ensure transition to AUTHSTATE_NONE.
            // OTR: "Transition authstate to AUTHSTATE_NONE."
            // OTR: "Regardless of whether the signature verifications succeed, the authstate variable is transitioned to AUTHSTATE_NONE."
            context.setState(StateInitial.empty());
        }
    }
}
