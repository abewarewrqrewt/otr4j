package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.profile.ClientProfile;
import net.java.otr4j.profile.ClientProfiles;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ProtocolException;

import static net.java.otr4j.api.Session.OTRv.SUPPORTED;
import static net.java.otr4j.io.messages.AuthIMessage.MESSAGE_AUTH_I;
import static net.java.otr4j.io.messages.AuthRMessage.MESSAGE_AUTH_R;
import static net.java.otr4j.io.messages.DHCommitMessage.MESSAGE_DH_COMMIT;
import static net.java.otr4j.io.messages.DHKeyMessage.MESSAGE_DHKEY;
import static net.java.otr4j.io.messages.DataMessage.MESSAGE_DATA;
import static net.java.otr4j.io.messages.IdentityMessage.MESSAGE_IDENTITY;
import static net.java.otr4j.io.messages.RevealSignatureMessage.MESSAGE_REVEALSIG;
import static net.java.otr4j.io.messages.SignatureMessage.MESSAGE_SIGNATURE;

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
     * @param input OTR input stream
     * @return Returns an OTR-encoded message as in-memory object.
     * @throws IOException        In case of issues during reading of the message bytes. (For example, missing bytes or
     *                            unexpected values.)
     * @throws OtrCryptoException In case of issues during reconstruction of cryptographic components of a message. (For
     *                            example, a bad public key.)
     */
    @Nonnull
    public static AbstractEncodedMessage read(@Nonnull final OtrInputStream input) throws IOException, OtrCryptoException {
        final int protocolVersion = input.readShort();
        if (!SUPPORTED.contains(protocolVersion)) {
            throw new ProtocolException("Unsupported protocol version " + protocolVersion);
        }
        final int messageType = input.readByte();
        final int senderInstanceTag;
        final int recipientInstanceTag;
        if (protocolVersion >= Session.OTRv.THREE) {
            senderInstanceTag = input.readInt();
            recipientInstanceTag = input.readInt();
        } else {
            senderInstanceTag = 0;
            recipientInstanceTag = 0;
        }
        switch (messageType) {
            case MESSAGE_DATA: {
                final int flags = input.readByte();
                final int senderKeyID = input.readInt();
                final int recipientKeyID = input.readInt();
                final DHPublicKey nextDH = input.readDHPublicKey();
                final byte[] ctr = input.readCtr();
                final byte[] encryptedMessage = input.readData();
                final byte[] mac = input.readMac();
                final byte[] oldMacKeys = input.readData();
                // The data message can only be validated where the current session keys are accessible. MAC validation
                // therefore happens in a later stage. For now we return an unvalidated data message instance.
                return new DataMessage(protocolVersion, flags, senderKeyID, recipientKeyID, nextDH, ctr,
                    encryptedMessage, mac, oldMacKeys, senderInstanceTag, recipientInstanceTag);
            }
            case MESSAGE_DH_COMMIT: {
                requireOTR23(protocolVersion);
                final byte[] dhPublicKeyEncrypted = input.readData();
                final byte[] dhPublicKeyHash = input.readData();
                return new DHCommitMessage(protocolVersion, dhPublicKeyHash, dhPublicKeyEncrypted, senderInstanceTag,
                    recipientInstanceTag);
            }
            case MESSAGE_DHKEY: {
                requireOTR23(protocolVersion);
                final DHPublicKey dhPublicKey = input.readDHPublicKey();
                return new DHKeyMessage(protocolVersion, dhPublicKey, senderInstanceTag, recipientInstanceTag);
            }
            case MESSAGE_REVEALSIG: {
                requireOTR23(protocolVersion);
                final byte[] revealedKey = input.readData();
                final byte[] xEncrypted = input.readData();
                final byte[] xEncryptedMac = input.readMac();
                return new RevealSignatureMessage(protocolVersion, xEncrypted, xEncryptedMac, revealedKey,
                    senderInstanceTag, recipientInstanceTag);
            }
            case MESSAGE_SIGNATURE: {
                requireOTR23(protocolVersion);
                final byte[] xEncryted = input.readData();
                final byte[] xEncryptedMac = input.readMac();
                return new SignatureMessage(protocolVersion, xEncryted, xEncryptedMac, senderInstanceTag,
                    recipientInstanceTag);
            }
            case MESSAGE_IDENTITY: {
                requireOTR4(protocolVersion);
                final ClientProfile profile = ClientProfiles.readFrom(input);
                final Point y = input.readPoint();
                final BigInteger b = input.readBigInt();
                return new IdentityMessage(protocolVersion, senderInstanceTag, recipientInstanceTag, profile, y, b);
            }
            case MESSAGE_AUTH_R: {
                requireOTR4(protocolVersion);
                final ClientProfile profile = ClientProfiles.readFrom(input);
                final Point x = input.readPoint();
                final BigInteger a = input.readBigInt();
                final OtrCryptoEngine4.Sigma sigma = OtrCryptoEngine4.Sigma.readFrom(input);
                return new AuthRMessage(protocolVersion, senderInstanceTag, recipientInstanceTag, profile, x, a, sigma);
            }
            case MESSAGE_AUTH_I: {
                requireOTR4(protocolVersion);
                final OtrCryptoEngine4.Sigma sigma = OtrCryptoEngine4.Sigma.readFrom(input);
                return new AuthIMessage(protocolVersion, senderInstanceTag, recipientInstanceTag, sigma);
            }
            default:
                throw new ProtocolException("Illegal message type.");
        }
    }

    private static void requireOTR23(final int version) throws ProtocolException {
        if (version != Session.OTRv.TWO && version != Session.OTRv.THREE) {
            throw new ProtocolException("The protocol version is illegal for this type of message. Expected protocol version 2 or 3.");
        }
    }

    private static void requireOTR4(final int version) throws ProtocolException {
        if (version != Session.OTRv.FOUR) {
            throw new ProtocolException("The protocol version is illegal for this type of message. Expected protocol version 4.");
        }
    }
}
