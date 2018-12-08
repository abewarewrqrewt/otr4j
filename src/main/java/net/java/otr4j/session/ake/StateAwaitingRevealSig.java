/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.UnsupportedTypeException;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.DHKeyMessage;
import net.java.otr4j.messages.RevealSignatureMessage;
import net.java.otr4j.messages.SignatureM;
import net.java.otr4j.messages.SignatureMessage;
import net.java.otr4j.messages.SignatureX;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.crypto.DHKeyPairOTR3.verifyDHPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine.SHA256_DIGEST_LENGTH_BYTES;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.messages.SignatureXs.readSignatureX;
import static net.java.otr4j.util.ByteArrays.requireLengthAtLeast;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;

/**
 * AKE state Awaiting Reveal Signature message, a.k.a.
 * AUTHSTATE_AWAITING_REVEALSIG.
 *
 * @author Danny van Heumen
 */
final class StateAwaitingRevealSig extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingRevealSig.class.getName());

    private static final int LOCAL_DH_PRIVATE_KEY_ID = 1;

    private final int version;
    private final DHKeyPairOTR3 keypair;
    private final byte[] remotePublicKeyHash;
    private final byte[] remotePublicKeyEncrypted;

    StateAwaitingRevealSig(final int version, @Nonnull final DHKeyPairOTR3 keypair,
            @Nonnull final byte[] remotePublicKeyHash, @Nonnull final byte[] remotePublicKeyEncrypted) {
        super();
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unsupported version specified");
        }
        this.version = version;
        this.keypair = Objects.requireNonNull(keypair);
        this.remotePublicKeyHash = requireLengthExactly(SHA256_DIGEST_LENGTH_BYTES, remotePublicKeyHash);
        // TODO can we make this argument verification more strict/accurate?
        this.remotePublicKeyEncrypted = requireLengthAtLeast(1, remotePublicKeyEncrypted);
    }

    @Nonnull
    @Override
    public Result handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message)
            throws OtrException, ProtocolException {

        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (message.protocolVersion != this.version) {
            throw new IllegalArgumentException("unexpected version");
        }
        if (message instanceof DHKeyMessage) {
            // OTR: "Ignore the message."
            LOGGER.log(Level.INFO, "Ignoring DHKey message.");
            return new Result();
        } else if (message instanceof RevealSignatureMessage) {
            try {
                return handleRevealSignatureMessage(context, (RevealSignatureMessage) message);
            } catch (final UnsupportedTypeException e) {
                throw new OtrException("Unsupported type of signature encountered.", e);
            }
        } else {
            LOGGER.log(Level.FINEST, "Only expected message types are DHKeyMessage and RevealSignatureMessage. Ignoring message with type: {0}", message.getType());
            return new Result();
        }
    }

    @Override
    public int getVersion() {
        return this.version;
    }

    @Nonnull
    private Result handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) {
        // OTR: "Retransmit your D-H Key Message (the same one as you sent when you entered AUTHSTATE_AWAITING_REVEALSIG).
        // Forget the old D-H Commit message, and use this new one instead."
        context.setAuthState(new StateAwaitingRevealSig(message.protocolVersion, this.keypair, message.dhPublicKeyHash,
                message.dhPublicKeyEncrypted));
        return new Result(new DHKeyMessage(message.protocolVersion, this.keypair.getPublic(),
                context.getSenderInstanceTag(), context.getReceiverInstanceTag()), null);
    }

    /**
     * Validate the received Reveal Signature message and construct the
     * Signature message to respond with.
     *
     * @param context Authentication context.
     * @param message Received Reveal Signature message.
     * @return Returns Signature message.
     * @throws OtrCryptoException Thrown in case of exceptions during validation
     * or signature message creation.
     * @throws ProtocolException Thrown in case of message content errors.
     */
    @Nonnull
    private Result handleRevealSignatureMessage(@Nonnull final AuthContext context,
            @Nonnull final RevealSignatureMessage message) throws OtrCryptoException,
            ProtocolException, UnsupportedTypeException {
        // OTR: "Use the received value of r to decrypt the value of gx received in the D-H Commit Message, and verify
        // the hash therein. Decrypt the encrypted signature, and verify the signature and the MACs."
        final DHPublicKey remoteDHPublicKey;
        final SharedSecret s;
        final SignatureX remoteMysteriousX;
        try {
            // Start validation of Reveal Signature message.
            // OTR: "Uses r to decrypt the value of gx sent earlier"
            final byte[] remotePublicKeyBytes = OtrCryptoEngine.aesDecrypt(message.revealedKey, null, this.remotePublicKeyEncrypted);
            // OTR: "Verifies that HASH(gx) matches the value sent earlier"
            final byte[] expectedRemotePublicKeyHash = OtrCryptoEngine.sha256Hash(remotePublicKeyBytes);
            OtrCryptoEngine.checkEquals(this.remotePublicKeyHash, expectedRemotePublicKeyHash, "Remote's public key hash failed validation.");
            // OTR: "Verifies that Bob's gx is a legal value (2 <= gx <= modulus-2)"
            final BigInteger dhPublicKeyMpi = new OtrInputStream(remotePublicKeyBytes).readBigInt();
            remoteDHPublicKey = verifyDHPublicKey(DHKeyPairOTR3.fromBigInteger(dhPublicKeyMpi));
            // OTR: "Compute the Diffie-Hellman shared secret s."
            // OTR: "Use s to compute an AES key c' and two MAC keys m1' and m2', as specified below."
            s = this.keypair.generateSharedSecret(remoteDHPublicKey);
            // OTR: "Uses m2 to verify MACm2(AESc(XB))"
            final OtrOutputStream xEncryptedEncoded = new OtrOutputStream().writeData(message.xEncrypted);
            final byte[] expectedXEncryptedMAC = OtrCryptoEngine.sha256Hmac160(xEncryptedEncoded.toByteArray(), s.m2());
            OtrCryptoEngine.checkEquals(message.xEncryptedMAC, expectedXEncryptedMAC, "xEncryptedMAC failed validation.");
            // OTR: "Uses c to decrypt AESc(XB) to obtain XB = pubB, keyidB, sigB(MB)"
            final byte[] remoteMysteriousXBytes = OtrCryptoEngine.aesDecrypt(s.c(), null, message.xEncrypted);
            remoteMysteriousX = readSignatureX(remoteMysteriousXBytes);
            // OTR: "Computes MB = MACm1(gx, gy, pubB, keyidB)"
            final SignatureM expectedM = new SignatureM(remoteDHPublicKey, this.keypair.getPublic(),
                    remoteMysteriousX.getLongTermPublicKey(), remoteMysteriousX.getDhKeyID());
            // OTR: "Uses pubB to verify sigB(MB)"
            final byte[] expectedSignature = OtrCryptoEngine.sha256Hmac(encode(expectedM), s.m1());
            remoteMysteriousX.verify(expectedSignature);
            LOGGER.finest("Signature verification succeeded.");
        } finally {
            // Ensure transition to AUTHSTATE_NONE.
            // OTR: "Transition authstate to AUTHSTATE_NONE."
            // OTR: "Regardless of whether the signature verifications succeed, the authstate variable is transitioned to AUTHSTATE_NONE."
            context.setAuthState(StateInitial.instance());
        }
        // OTR: "Transition msgstate to MSGSTATE_ENCRYPTED."
        // Transition to ENCRYPTED message state.
        final SecurityParameters params = new SecurityParameters(this.version, this.keypair,
                remoteMysteriousX.getLongTermPublicKey(), remoteDHPublicKey, s);
        // OTR: "Reply with a Signature Message."
        // Start construction of Signature message.
        final DSAKeyPair localLongTermKeyPair = context.getLocalKeyPair();
        // OTR: "Select keyidA, a serial number for the D-H key computed earlier. It is an INT, and must be greater than 0."
        // OTR: "Compute the 32-byte value MA to be the SHA256-HMAC of the following data, using the key m1':
        // gy (MPI), gx (MPI), pubA (PUBKEY), keyidA (INT)"
        final SignatureM signatureM = new SignatureM(this.keypair.getPublic(), remoteDHPublicKey,
                localLongTermKeyPair.getPublic(), LOCAL_DH_PRIVATE_KEY_ID);
        final byte[] mhash = OtrCryptoEngine.sha256Hmac(encode(signatureM), s.m1p());
        // OTR: "Let XA be the following structure: pubA (PUBKEY), keyidA (INT), sigA(MA) (SIG)"
        final byte[] signature = localLongTermKeyPair.sign(mhash);
        final SignatureX mysteriousX = new SignatureX(localLongTermKeyPair.getPublic(), LOCAL_DH_PRIVATE_KEY_ID,
                signature);
        // OTR: "Encrypt XA using AES128-CTR with key c' and initial counter value 0."
        final byte[] xEncrypted = OtrCryptoEngine.aesEncrypt(s.cp(), null, encode(mysteriousX));
        // OTR: "Encode this encrypted value as the DATA field."
        // OTR: "This is the SHA256-HMAC-160 (that is, the first 160 bits of the SHA256-HMAC) of the encrypted signature field (including the four-byte length), using the key m2'."
        final OtrOutputStream xEncryptedEncoded = new OtrOutputStream().writeData(xEncrypted);
        final byte[] xEncryptedHash = OtrCryptoEngine.sha256Hmac160(xEncryptedEncoded.toByteArray(), s.m2p());
        LOGGER.finest("Creating signature message for response.");
        // OTR: "Sends Bob AESc'(XA), MACm2'(AESc'(XA))"
        return new Result(new SignatureMessage(this.version, xEncrypted, xEncryptedHash,
                context.getSenderInstanceTag(), context.getReceiverInstanceTag()), params);
    }
}
