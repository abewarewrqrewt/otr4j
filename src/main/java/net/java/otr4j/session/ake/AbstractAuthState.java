/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.IdentityMessage;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.util.logging.Logger;

import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;
import static net.java.otr4j.crypto.DHKeyPairOTR3.verifyDHPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesEncrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha256Hash;
import static net.java.otr4j.util.SecureRandoms.randomBytes;

/**
 * Abstract AuthState implementation that provides authentication initiation
 * as this is supported in any state and is always processed in the same manner.
 *
 * @author Danny van Heumen
 */
abstract class AbstractAuthState implements AuthState {

    private static final Logger LOGGER = Logger.getLogger(AbstractAuthState.class.getName());

    @Nonnull
    @Override
    public AbstractEncodedMessage initiate(@Nonnull final AuthContext context, final int version,
            @Nonnull final InstanceTag receiverTag, @Nonnull final String queryTag) {
        if (!Version.SUPPORTED.contains(version)) {
            throw new IllegalArgumentException("unknown or unsupported protocol version");
        }
        if (version == Version.TWO || version == Session.Version.THREE) {
            return initiateVersion3(context, version, receiverTag);
        } else if (version == Version.FOUR) {
            return initiateVersion4(context, receiverTag, queryTag);
        } else {
            throw new UnsupportedOperationException("Unsupported protocol version.");
        }
    }

    @Nonnull
    private DHCommitMessage initiateVersion3(@Nonnull final AuthContext context, final int version, @Nonnull final InstanceTag receiverTag) {
        // OTR: "Choose a random value x (at least 320 bits)"
        final DHKeyPairOTR3 keypair = generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        final DHPublicKey localDHPublicKey = keypair.getPublic();
        try {
            verifyDHPublicKey(localDHPublicKey);
        } catch (final OtrCryptoException ex) {
            // Caught and handled here as all components are constructed here
            // and failure should thus be considered a programming error.
            throw new IllegalStateException("Failed to generate valid local DH keypair.", ex);
        }
        // OTR: "Serialize gx as an MPI, gxmpi. [gxmpi will probably be 196 bytes long, starting with "\x00\x00\x00\xc0".]"
        final byte[] publicKeyBytes = new OtrOutputStream().writeBigInt(localDHPublicKey.getY()).toByteArray();
        // OTR: "Encrypt gxmpi using AES128-CTR, with key r and initial counter value 0. The result will be the same length as gxmpi."
        final byte[] publicKeyEncrypted;
        // OTR: "Choose a random value r (128 bits)"
        final byte[] r = randomBytes(context.secureRandom(), new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH]);
        try {
            publicKeyEncrypted = aesEncrypt(r, null, publicKeyBytes);
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to encrypt public key bytes.", ex);
        }
        // OTR: "This is the SHA256 hash of gxmpi."
        final byte[] publicKeyHash = sha256Hash(publicKeyBytes);
        // OTR: "Sends Alice AESr(gx), HASH(gx)"
        final DHCommitMessage dhcommit = new DHCommitMessage(version, publicKeyHash, publicKeyEncrypted,
                context.getSenderInstanceTag(), receiverTag);
        LOGGER.finest("Sending DH commit message.");
        context.setState(new StateAwaitingDHKey(version, keypair, r));
        return dhcommit;
    }

    @Nonnull
    private IdentityMessage initiateVersion4(@Nonnull final AuthContext context, @Nonnull final InstanceTag receiverTag,
            @Nonnull final String queryTag) {
        final ECDHKeyPair ourECDHkeyPair = ECDHKeyPair.generate(context.secureRandom());
        final DHKeyPair ourDHkeyPair = DHKeyPair.generate(context.secureRandom());
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final IdentityMessage message = new IdentityMessage(Version.FOUR, context.getSenderInstanceTag(),
                receiverTag, profilePayload, ourECDHkeyPair.getPublicKey(), ourDHkeyPair.getPublicKey());
        context.setState(new StateAwaitingAuthR(ourECDHkeyPair, ourDHkeyPair, profilePayload, queryTag, message));
        return message;
    }
}
