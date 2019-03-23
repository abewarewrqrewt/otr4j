/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.net.ProtocolException;

import static java.math.BigInteger.ZERO;
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
     * @param message the encoded message instance to be parsed.
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
    @Nonnull
    public static AbstractEncodedMessage parseEncodedMessage(final EncodedMessage message) throws OtrCryptoException, ProtocolException,
            UnsupportedLengthException, ValidationException {
        switch (message.type) {
        case MESSAGE_DATA: {
            switch (message.version) {
            case 0:
                throw new IllegalStateException("BUG: Unexpected protocol version found. Zero is not valid as a protocol version. It is used in other parts of otr4j as indicator that OTR is not active.");
            case Version.ONE:
                throw new UnsupportedOperationException("Illegal protocol version: version 1 is no longer supported.");
            case Version.TWO: // intentional fall-through
            case Version.THREE: {
                final byte flags = message.payload.readByte();
                final int senderKeyID = message.payload.readInt();
                final int recipientKeyID = message.payload.readInt();
                final DHPublicKey nextDH = message.payload.readDHPublicKey();
                final byte[] ctr = message.payload.readCtr();
                final byte[] encryptedMessage = message.payload.readData();
                final byte[] mac = message.payload.readMac();
                final byte[] oldMacKeys = message.payload.readData();
                // The data message can only be validated where the current session keys are accessible. MAC validation
                // therefore happens in a later stage. For now we return an unvalidated data message instance.
                return new DataMessage(message.version, flags, senderKeyID, recipientKeyID, nextDH, ctr, encryptedMessage, mac,
                        oldMacKeys, message.senderTag, message.receiverTag);
            }
            case Version.FOUR: {
                final byte flags = message.payload.readByte();
                final int pn = message.payload.readInt();
                final int i = message.payload.readInt();
                final int j = message.payload.readInt();
                final Point ecdhPublicKey = message.payload.readPoint();
                final BigInteger dhPublicKey = message.payload.readBigInt();
                final byte[] ciphertext = message.payload.readData();
                final byte[] authenticator = message.payload.readMacOTR4();
                final byte[] revealedMacs = message.payload.readData();
                // We only verify the format of the data message, but do not perform the validation actions yet.
                // Validation is delayed until a later point as we are missing context information for full validation.
                return new DataMessage4(message.version, message.senderTag, message.receiverTag, flags, pn, i, j,
                        ecdhPublicKey, ZERO.equals(dhPublicKey) ? null : dhPublicKey, ciphertext, authenticator,
                        revealedMacs);
            }
            default:
                throw new UnsupportedOperationException("BUG: Future protocol versions are not supported. We should not have reached this state.");
            }
        }
        case MESSAGE_DH_COMMIT: {
            requireOTR23(message.version);
            final byte[] dhPublicKeyEncrypted = message.payload.readData();
            final byte[] dhPublicKeyHash = message.payload.readData();
            return new DHCommitMessage(message.version, dhPublicKeyHash, dhPublicKeyEncrypted, message.senderTag,
                    message.receiverTag);
        }
        case MESSAGE_DHKEY: {
            requireOTR23(message.version);
            final DHPublicKey dhPublicKey = message.payload.readDHPublicKey();
            return new DHKeyMessage(message.version, dhPublicKey, message.senderTag, message.receiverTag);
        }
        case MESSAGE_REVEALSIG: {
            requireOTR23(message.version);
            final byte[] revealedKey = message.payload.readData();
            final byte[] xEncrypted = message.payload.readData();
            final byte[] xEncryptedMac = message.payload.readMac();
            return new RevealSignatureMessage(message.version, xEncrypted, xEncryptedMac, revealedKey, message.senderTag,
                    message.receiverTag);
        }
        case MESSAGE_SIGNATURE: {
            requireOTR23(message.version);
            final byte[] xEncryted = message.payload.readData();
            final byte[] xEncryptedMac = message.payload.readMac();
            return new SignatureMessage(message.version, xEncryted, xEncryptedMac, message.senderTag, message.receiverTag);
        }
        case MESSAGE_IDENTITY: {
            requireOTR4(message.version);
            final ClientProfilePayload profile = ClientProfilePayload.readFrom(message.payload);
            final Point y = message.payload.readPoint();
            final BigInteger b = message.payload.readBigInt();
            final Point ourFirstECDHPublicKey = message.payload.readPoint();
            final BigInteger ourFirstDHPublicKey = message.payload.readBigInt();
            return new IdentityMessage(message.version, message.senderTag, message.receiverTag, profile,
                    y, b, ourFirstECDHPublicKey, ourFirstDHPublicKey);
        }
        case MESSAGE_AUTH_R: {
            requireOTR4(message.version);
            final ClientProfilePayload profile = ClientProfilePayload.readFrom(message.payload);
            final Point x = message.payload.readPoint();
            final BigInteger a = message.payload.readBigInt();
            final Sigma sigma = Sigma.readFrom(message.payload);
            final Point ourFirstECDHPublicKey = message.payload.readPoint();
            final BigInteger ourFirstDHPublicKey = message.payload.readBigInt();
            return new AuthRMessage(message.version, message.senderTag, message.receiverTag, profile, x, a, sigma,
                    ourFirstECDHPublicKey, ourFirstDHPublicKey);
        }
        case MESSAGE_AUTH_I: {
            requireOTR4(message.version);
            final Sigma sigma = Sigma.readFrom(message.payload);
            return new AuthIMessage(message.version, message.senderTag, message.receiverTag, sigma);
        }
        default:
            throw new ProtocolException("Illegal message type: " + message.type);
        }
    }

    private static void requireOTR23(final int version) throws ProtocolException {
        if (version != Version.TWO && version != Version.THREE) {
            throw new ProtocolException("The protocol version is illegal for this type of message. Expected protocol version 2 or 3.");
        }
    }

    private static void requireOTR4(final int version) throws ProtocolException {
        if (version != Version.FOUR) {
            throw new ProtocolException("The protocol version is illegal for this type of message. Expected protocol version 4.");
        }
    }

    /**
     * Check if the message type is of the DH-Key message.
     *
     * @param message the encoded message
     * @return Returns true iff DH-Key message or false otherwise.
     */
    @CheckReturnValue
    public static boolean checkDHKeyMessage(@Nonnull final EncodedMessage message) {
        return message.type == MESSAGE_DHKEY;
    }

    /**
     * Check if the message type is of the Auth-R message.
     *
     * @param message the encoded message
     * @return Returns true iff Auth-R message or false otherwise.
     */
    @CheckReturnValue
    public static boolean checkAuthRMessage(@Nonnull final EncodedMessage message) {
        return message.type == MESSAGE_AUTH_R;
    }
}
