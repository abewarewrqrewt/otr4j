/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.DHKeyMessage;
import net.java.otr4j.messages.RevealSignatureMessage;
import net.java.otr4j.messages.SignatureM;
import net.java.otr4j.messages.SignatureX;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;
import static net.java.otr4j.crypto.DHKeyPairOTR3.verifyDHPublicKey;
import static net.java.otr4j.io.OtrEncodables.encode;

/**
 * AKE state Awaiting D-H Key message, a.k.a. AUTHSTATE_AWAITING_DHKEY.
 *
 * @author Danny van Heumen
 */
final class StateAwaitingDHKey extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingDHKey.class.getName());

    private static final int LOCAL_DH_PRIVATE_KEY_ID = 1;

    private final int version;
    private final DHKeyPairOTR3 keypair;
    private final byte[] r;

    @SuppressWarnings("PMD.ArrayIsStoredDirectly")
    StateAwaitingDHKey(final int version, @Nonnull final DHKeyPairOTR3 keypair, @Nonnull final byte[] r) {
        super();
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("unsupported version specified");
        }
        this.version = version;
        this.keypair = Objects.requireNonNull(keypair);
        if (r.length != OtrCryptoEngine.AES_KEY_BYTE_LENGTH) {
            throw new IllegalArgumentException("Invalid random value: expected 128-bit random value.");
        }
        this.r = r;
    }

    @Nonnull
    @Override
    public Result handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException {
        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (message.protocolVersion != this.version) {
            throw new IllegalArgumentException("unexpected version");
        }
        if (message instanceof DHKeyMessage) {
            return handleDHKeyMessage(context, (DHKeyMessage) message);
        } else {
            // OTR: "Ignore the message."
            LOGGER.log(Level.FINEST, "Only expected message is DHKeyMessage. Ignoring message with type: {0}", message.getType());
            return new Result();
        }
    }

    @Override
    public int getVersion() {
        return this.version;
    }

    @Nonnull
    private Result handleDHCommitMessage(@Nonnull final AuthContext context,
            @Nonnull final DHCommitMessage message) throws OtrCryptoException {
        // OTR: "This is the trickiest transition in the whole protocol. It indicates that you have already sent a D-H Commit message
        // to your correspondent, but that he either didn't receive it, or just didn't receive it yet, and has sent you one as well.
        // The symmetry will be broken by comparing the hashed gx you sent in your D-H Commit Message with the one you received,
        // considered as 32-byte unsigned big-endian values."
        final byte[] publicKeyBytes = new OtrOutputStream().writeBigInt(keypair.getPublic().getY()).toByteArray();
        final byte[] publicKeyHash = OtrCryptoEngine.sha256Hash(publicKeyBytes);
        final BigInteger localKeyHashBigInt = new BigInteger(1, publicKeyHash);
        final BigInteger remoteKeyHashBigInt = new BigInteger(1, message.dhPublicKeyHash);
        if (localKeyHashBigInt.compareTo(remoteKeyHashBigInt) > 0) {
            // OTR: "If yours is the higher hash value: Ignore the incoming D-H Commit message, but resend your D-H Commit message."
            LOGGER.finest("Ignored the incoming D-H Commit message, but resent our D-H Commit message.");
            final byte[] publicKeyEncrypted = OtrCryptoEngine.aesEncrypt(this.r, null, publicKeyBytes);
            // Special-case repeat of your D-H Commit message: instead of
            // resending D-H Commit message to every instance, now dedicate it
            // to the sender of the received D-H Commit message. That way, we do
            // not needlessly trigger other OTRv2 and OTRv3 clients.
            return new Result(new DHCommitMessage(this.version, publicKeyHash, publicKeyEncrypted,
                    context.getSenderInstanceTag(), message.senderInstanceTag), null);
        } else {
            // OTR: "Otherwise: Forget your old gx value that you sent (encrypted) earlier, and pretend you're in AUTHSTATE_NONE;
            // i.e. reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG."
            LOGGER.finest("Forgetting old gx value that we sent (encrypted) earlier, and pretended we're in AUTHSTATE_NONE -> Sending DH key.");
            // OTR: "Choose a random value y (at least 320 bits), and calculate gy."
            final DHKeyPairOTR3 newKeypair = generateDHKeyPair(context.secureRandom());
            context.setAuthState(new StateAwaitingRevealSig(message.protocolVersion, newKeypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
            return new Result(new DHKeyMessage(message.protocolVersion, newKeypair.getPublic(),
                    context.getSenderInstanceTag(), context.getReceiverInstanceTag()), null);
        }
    }

    @Nonnull
    private Result handleDHKeyMessage(@Nonnull final AuthContext context,
            @Nonnull final DHKeyMessage message) throws OtrCryptoException {
        // OTR: "Reply with a Reveal Signature Message and transition authstate to AUTHSTATE_AWAITING_SIG."
        // OTR: "Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)"
        verifyDHPublicKey(message.dhPublicKey);
        final DSAKeyPair longTermKeyPair = context.getLocalKeyPair();
        // OTR: "Compute the Diffie-Hellman shared secret s"
        // OTR: "Use s to compute an AES key c and two MAC keys m1 and m2, as specified below."
        final SharedSecret s = this.keypair.generateSharedSecret(message.dhPublicKey);
        // OTR: "Select keyidB, a serial number for the D-H key computed earlier. It is an INT, and must be greater than 0."
        // OTR: "Compute the 32-byte value MB to be the SHA256-HMAC of the following data, using the key m1: gx (MPI), gy (MPI), pubB (PUBKEY), keyidB (INT)"
        final SignatureM sigM = new SignatureM(this.keypair.getPublic(), message.dhPublicKey,
                longTermKeyPair.getPublic(), LOCAL_DH_PRIVATE_KEY_ID);
        final byte[] mhash = OtrCryptoEngine.sha256Hmac(encode(sigM), s.m1());
        // OTR: "Let XB be the following structure: pubB (PUBKEY), keyidB (INT), sigB(MB) (SIG)"
        final byte[] signature = longTermKeyPair.sign(mhash);
        final SignatureX mysteriousX = new SignatureX(longTermKeyPair.getPublic(), LOCAL_DH_PRIVATE_KEY_ID,
                signature);
        // OTR: "Encrypt XB using AES128-CTR with key c and initial counter value 0."
        final byte[] xEncrypted = OtrCryptoEngine.aesEncrypt(s.c(), null, encode(mysteriousX));
        // OTR: "This is the SHA256-HMAC-160 (that is, the first 160 bits of the SHA256-HMAC) of the encrypted signature field (including the four-byte length), using the key m2."
        final OtrOutputStream xEncryptedEncoded = new OtrOutputStream().writeData(xEncrypted);
        final byte[] xEncryptedHash = OtrCryptoEngine.sha256Hmac160(xEncryptedEncoded.toByteArray(), s.m2());
        // OTR: "Sends Alice r, AESc(XB), MACm2(AESc(XB))"
        final RevealSignatureMessage revealSigMessage = new RevealSignatureMessage(this.version, xEncrypted,
                xEncryptedHash, this.r, context.getSenderInstanceTag(), context.getReceiverInstanceTag());
        context.setAuthState(new StateAwaitingSig(this.version, this.keypair, message.dhPublicKey, s, revealSigMessage));
        return new Result(revealSigMessage, null);
    }
}
