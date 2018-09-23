/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureM;
import net.java.otr4j.io.messages.SignatureX;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    private final KeyPair keypair;
    private final byte[] r;

    @SuppressWarnings("PMD.ArrayIsStoredDirectly")
    StateAwaitingDHKey(final int version, @Nonnull final KeyPair keypair, @Nonnull final byte[] r) {
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

    @Nullable
    @Override
    public AbstractEncodedMessage handle(@Nonnull final AuthContext context, @Nonnull final AbstractEncodedMessage message) throws OtrCryptoException {
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
            return null;
        }
    }

    @Override
    public int getVersion() {
        return this.version;
    }

    @Nonnull
    private AbstractEncodedMessage handleDHCommitMessage(@Nonnull final AuthContext context, @Nonnull final DHCommitMessage message) throws OtrCryptoException {
        // OTR: "This is the trickiest transition in the whole protocol. It indicates that you have already sent a D-H Commit message
        // to your correspondent, but that he either didn't receive it, or just didn't receive it yet, and has sent you one as well.
        // The symmetry will be broken by comparing the hashed gx you sent in your D-H Commit Message with the one you received,
        // considered as 32-byte unsigned big-endian values."
        final byte[] publicKeyBytes = new OtrOutputStream().writeBigInt(((DHPublicKey) keypair.getPublic()).getY())
            .toByteArray();
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
            return new DHCommitMessage(this.version, publicKeyHash, publicKeyEncrypted, context.getSenderInstanceTag(),
                    message.senderInstanceTag);
        } else {
            // OTR: "Otherwise: Forget your old gx value that you sent (encrypted) earlier, and pretend you're in AUTHSTATE_NONE;
            // i.e. reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG."
            LOGGER.finest("Forgetting old gx value that we sent (encrypted) earlier, and pretended we're in AUTHSTATE_NONE -> Sending DH key.");
            // OTR: "Choose a random value y (at least 320 bits), and calculate gy."
            final KeyPair newKeypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
            context.setState(new StateAwaitingRevealSig(message.protocolVersion, newKeypair, message.dhPublicKeyHash, message.dhPublicKeyEncrypted));
            return new DHKeyMessage(message.protocolVersion, (DHPublicKey) newKeypair.getPublic(),
                    context.getSenderInstanceTag(), context.getReceiverInstanceTag());
        }
    }

    @Nonnull
    private RevealSignatureMessage handleDHKeyMessage(@Nonnull final AuthContext context, @Nonnull final DHKeyMessage message) throws OtrCryptoException {
        // OTR: "Reply with a Reveal Signature Message and transition authstate to AUTHSTATE_AWAITING_SIG."
        // OTR: "Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)"
        OtrCryptoEngine.verify(message.dhPublicKey);
        final KeyPair longTermKeyPair = context.getLocalKeyPair();
        // OTR: "Compute the Diffie-Hellman shared secret s"
        // OTR: "Use s to compute an AES key c and two MAC keys m1 and m2, as specified below."
        final SharedSecret s = OtrCryptoEngine.generateSecret(this.keypair.getPrivate(), message.dhPublicKey);
        // OTR: "Select keyidB, a serial number for the D-H key computed earlier. It is an INT, and must be greater than 0."
        // OTR: "Compute the 32-byte value MB to be the SHA256-HMAC of the following data, using the key m1: gx (MPI), gy (MPI), pubB (PUBKEY), keyidB (INT)"
        final SignatureM sigM = new SignatureM((DHPublicKey) this.keypair.getPublic(), message.dhPublicKey,
                (DSAPublicKey) longTermKeyPair.getPublic(), LOCAL_DH_PRIVATE_KEY_ID);
        final byte[] mhash = OtrCryptoEngine.sha256Hmac(encode(sigM), s.m1());
        // OTR: "Let XB be the following structure: pubB (PUBKEY), keyidB (INT), sigB(MB) (SIG)"
        final byte[] signature = OtrCryptoEngine.sign(mhash, (DSAPrivateKey) longTermKeyPair.getPrivate());
        final SignatureX mysteriousX = new SignatureX((DSAPublicKey) longTermKeyPair.getPublic(),
                LOCAL_DH_PRIVATE_KEY_ID, signature);
        // OTR: "Encrypt XB using AES128-CTR with key c and initial counter value 0."
        final byte[] xEncrypted = OtrCryptoEngine.aesEncrypt(s.c(), null, encode(mysteriousX));
        // OTR: "This is the SHA256-HMAC-160 (that is, the first 160 bits of the SHA256-HMAC) of the encrypted signature field (including the four-byte length), using the key m2."
        final OtrOutputStream xEncryptedEncoded = new OtrOutputStream().writeData(xEncrypted);
        final byte[] xEncryptedHash = OtrCryptoEngine.sha256Hmac160(xEncryptedEncoded.toByteArray(), s.m2());
        // OTR: "Sends Alice r, AESc(XB), MACm2(AESc(XB))"
        final RevealSignatureMessage revealSigMessage = new RevealSignatureMessage(
                this.version, xEncrypted, xEncryptedHash, this.r, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag());
        context.setState(new StateAwaitingSig(this.version, this.keypair,
                message.dhPublicKey, s, revealSigMessage));
        return revealSigMessage;
    }
}
