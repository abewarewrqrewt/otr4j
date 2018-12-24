/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.net.ProtocolException;

import static java.math.BigInteger.ZERO;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.messages.AuthIMessage.MESSAGE_AUTH_I;
import static net.java.otr4j.messages.AuthRMessage.MESSAGE_AUTH_R;
import static net.java.otr4j.messages.DHCommitMessage.MESSAGE_DH_COMMIT;
import static net.java.otr4j.messages.DHKeyMessage.MESSAGE_DHKEY;
import static net.java.otr4j.messages.DataMessage.MESSAGE_DATA;
import static net.java.otr4j.messages.IdentityMessage.MESSAGE_IDENTITY;
import static net.java.otr4j.messages.RevealSignatureMessage.MESSAGE_REVEALSIG;
import static net.java.otr4j.messages.SignatureMessage.MESSAGE_SIGNATURE;

/**
 * Parser for OTR encoded message types.
 */
public final class EncodedMessageParser {

    private EncodedMessageParser() {
        // No need to instantiate utility class.
    }

    /**
     * Read an OTR-encoded message from the provided input stream.
     * <p>
     * The encoded message bytes are read from the input stream, interpreted and a composed in-memory message object is
     * constructed and returned. Any validation data that might be contained in this message is NOT processed. Message
     * received from the parser can therefore not yet be trusted on their content.
     *
     * @param version             the protocol version
     * @param type                the (encoded) message type
     * @param senderInstanceTag   the sender instance tag (may be ZERO tag)
     * @param receiverInstanceTag the receiver instance tag (may be ZERO tag)
     * @param payload             the payload of the encoded message that corresponds with the message type
     * @return Returns an OTR-encoded message as in-memory object.
     * @throws ProtocolException          In case of issues during reading of the message bytes. (For example, missing
     *                                    bytes or unexpected values.)
     * @throws OtrCryptoException         In case of issues during reconstruction of cryptographic components of a
     *                                    message. (For example, a bad public key.)
     * @throws UnsupportedLengthException In case of exceptionally long message, which surpasses the limitation of
     *                                    otr4j.
     * @throws ValidationException        In case a message was successfully read and parsed but the contents of the
     *                                    message do not result in a valid composition.
     */
    // FIXME unit test deserialization of OTRv4 (data) messages.
    // TODO consider making a hard split between OTRv2, OTRv3 and OTRv4 parsing based on protocol version to prevent unsupported message types from being parsed.
    @Nonnull
    public static AbstractEncodedMessage parseEncodedMessage(final int version, final int type,
            @Nonnull final InstanceTag senderInstanceTag, @Nonnull final InstanceTag receiverInstanceTag,
            @Nonnull final OtrInputStream payload) throws OtrCryptoException, ProtocolException,
            UnsupportedLengthException, ValidationException {
        requireNonNull(senderInstanceTag);
        requireNonNull(receiverInstanceTag);
        requireNonNull(payload);
        switch (type) {
        case MESSAGE_DATA: {
            switch (version) {
            case 0:
                throw new IllegalStateException("BUG: Unexpected protocol version found. Zero is not valid as a protocol version. It is used in other parts of otr4j as indicator that OTR is not active.");
            case Version.ONE:
                throw new UnsupportedOperationException("Illegal protocol version: version 1 is no longer supported.");
            case Session.Version.TWO:
            case Session.Version.THREE: {
                final byte flags = payload.readByte();
                final int senderKeyID = payload.readInt();
                final int recipientKeyID = payload.readInt();
                final DHPublicKey nextDH = payload.readDHPublicKey();
                final byte[] ctr = payload.readCtr();
                final byte[] encryptedMessage = payload.readData();
                final byte[] mac = payload.readMac();
                final byte[] oldMacKeys = payload.readData();
                // The data message can only be validated where the current session keys are accessible. MAC validation
                // therefore happens in a later stage. For now we return an unvalidated data message instance.
                return new DataMessage(version, flags, senderKeyID, recipientKeyID, nextDH, ctr, encryptedMessage, mac,
                        oldMacKeys, senderInstanceTag, receiverInstanceTag);
            }
            case Session.Version.FOUR: {
                final byte flags = payload.readByte();
                final int pn = payload.readInt();
                final int i = payload.readInt();
                final int j = payload.readInt();
                final Point ecdhPublicKey = payload.readPoint();
                final BigInteger dhPublicKey = payload.readBigInt();
                final byte[] nonce = payload.readNonce();
                final byte[] ciphertext = payload.readData();
                final byte[] authenticator = payload.readMacOTR4();
                final byte[] revealedMacs = payload.readData();
                // We only verify the format of the data message, but do not perform the validation actions yet.
                // Validation is delayed until a later point as we are missing context information for full validation.
                return new DataMessage4(version, senderInstanceTag, receiverInstanceTag, flags, pn, i, j, ecdhPublicKey,
                        ZERO.equals(dhPublicKey) ? null : dhPublicKey, nonce, ciphertext, authenticator, revealedMacs);
            }
            default:
                throw new UnsupportedOperationException("BUG: Future protocol versions are not supported. We should not have reached this state.");
            }
        }
        case MESSAGE_DH_COMMIT: {
            requireOTR23(version);
            final byte[] dhPublicKeyEncrypted = payload.readData();
            final byte[] dhPublicKeyHash = payload.readData();
            return new DHCommitMessage(version, dhPublicKeyHash, dhPublicKeyEncrypted, senderInstanceTag,
                receiverInstanceTag);
        }
        case MESSAGE_DHKEY: {
            requireOTR23(version);
            final DHPublicKey dhPublicKey = payload.readDHPublicKey();
            return new DHKeyMessage(version, dhPublicKey, senderInstanceTag, receiverInstanceTag);
        }
        case MESSAGE_REVEALSIG: {
            requireOTR23(version);
            final byte[] revealedKey = payload.readData();
            final byte[] xEncrypted = payload.readData();
            final byte[] xEncryptedMac = payload.readMac();
            return new RevealSignatureMessage(version, xEncrypted, xEncryptedMac, revealedKey, senderInstanceTag,
                    receiverInstanceTag);
        }
        case MESSAGE_SIGNATURE: {
            requireOTR23(version);
            final byte[] xEncryted = payload.readData();
            final byte[] xEncryptedMac = payload.readMac();
            return new SignatureMessage(version, xEncryted, xEncryptedMac, senderInstanceTag, receiverInstanceTag);
        }
        case MESSAGE_IDENTITY: {
            requireOTR4(version);
            final ClientProfilePayload profile = ClientProfilePayload.readFrom(payload);
            final Point y = payload.readPoint();
            final BigInteger b = payload.readBigInt();
            final Point ourFirstECDHPublicKey = payload.readPoint();
            final BigInteger ourFirstDHPublicKey = payload.readBigInt();
            return new IdentityMessage(version, senderInstanceTag, receiverInstanceTag, profile, y, b,
                    ourFirstECDHPublicKey, ourFirstDHPublicKey);
        }
        case MESSAGE_AUTH_R: {
            requireOTR4(version);
            final ClientProfilePayload profile = ClientProfilePayload.readFrom(payload);
            final Point x = payload.readPoint();
            final BigInteger a = payload.readBigInt();
            final Sigma sigma = Sigma.readFrom(payload);
            final Point ourFirstECDHPublicKey = payload.readPoint();
            final BigInteger ourFirstDHPublicKey = payload.readBigInt();
            return new AuthRMessage(version, senderInstanceTag, receiverInstanceTag, profile, x, a, sigma,
                    ourFirstECDHPublicKey, ourFirstDHPublicKey);
        }
        case MESSAGE_AUTH_I: {
            requireOTR4(version);
            final Sigma sigma = Sigma.readFrom(payload);
            return new AuthIMessage(version, senderInstanceTag, receiverInstanceTag, sigma);
        }
        default:
            throw new ProtocolException("Illegal message type: " + type);
        }
    }

    private static void requireOTR23(final int version) throws ProtocolException {
        if (version != Session.Version.TWO && version != Session.Version.THREE) {
            throw new ProtocolException("The protocol version is illegal for this type of message. Expected protocol version 2 or 3.");
        }
    }

    private static void requireOTR4(final int version) throws ProtocolException {
        if (version != Session.Version.FOUR) {
            throw new ProtocolException("The protocol version is illegal for this type of message. Expected protocol version 4.");
        }
    }
}
