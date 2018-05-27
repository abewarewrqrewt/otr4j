/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.IdentityMessage;
import net.java.otr4j.profile.ClientProfile;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.security.KeyPair;
import java.util.logging.Logger;

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
        if (!Session.OTRv.SUPPORTED.contains(version)) {
            throw new IllegalArgumentException("unknown or unsupported protocol version");
        }
        if (version == Session.OTRv.TWO || version == Session.OTRv.THREE) {
            return initiateVersion3(context, version, receiverTag);
        }
        return initiateVersion4(context, receiverTag, queryTag);
    }

    @Nonnull
    private DHCommitMessage initiateVersion3(@Nonnull final AuthContext context, final int version, @Nonnull final InstanceTag receiverTag) {
        // OTR: "Choose a random value x (at least 320 bits)"
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        // OTR: "Choose a random value r (128 bits)"
        final byte[] r = OtrCryptoEngine.random(context.secureRandom(),
                new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH]);
        final DHPublicKey localDHPublicKey = (DHPublicKey) keypair.getPublic();
        try {
            OtrCryptoEngine.verify(localDHPublicKey);
        } catch (final OtrCryptoException ex) {
            // Caught and handled here as all components are constructed here
            // and failure should thus be considered a programming error.
            throw new IllegalStateException("Failed to generate valid local DH keypair.", ex);
        }
        // OTR: "Serialize gx as an MPI, gxmpi. [gxmpi will probably be 196 bytes long, starting with "\x00\x00\x00\xc0".]"
        final byte[] publicKeyBytes = SerializationUtils.writeMpi(localDHPublicKey.getY());
        // OTR: "This is the SHA256 hash of gxmpi."
        final byte[] publicKeyHash = OtrCryptoEngine.sha256Hash(publicKeyBytes);
        // OTR: "Encrypt gxmpi using AES128-CTR, with key r and initial counter value 0. The result will be the same length as gxmpi."
        final byte[] publicKeyEncrypted;
        try {
            publicKeyEncrypted = OtrCryptoEngine.aesEncrypt(r, null, publicKeyBytes);
        } catch (final OtrCryptoException ex) {
            throw new IllegalStateException("Failed to encrypt public key bytes.", ex);
        }
        // OTR: "Sends Alice AESr(gx), HASH(gx)"
        final DHCommitMessage dhcommit = new DHCommitMessage(version,
                publicKeyHash, publicKeyEncrypted, context.getSenderInstanceTag().getValue(),
                receiverTag.getValue());
        LOGGER.finest("Sending DH commit message.");
        context.setState(new StateAwaitingDHKey(version, keypair, r));
        return dhcommit;
    }

    @Nonnull
    private IdentityMessage initiateVersion4(@Nonnull final AuthContext context, @Nonnull final InstanceTag receiverTag,
                                             @Nonnull final String queryTag) {
        final ECDHKeyPair ourECDHkeyPair = ECDHKeyPair.generate(context.secureRandom());
        final DHKeyPair ourDHkeyPair = DHKeyPair.generate(context.secureRandom());
        // TODO Currently we "reuse" the sender instance tag from the context. Should we do this or is it better to generate a new sender tag for each conversation? (Probably not)
        final int senderTagValue = context.getSenderInstanceTag().getValue();
        final int receiverTagValue = receiverTag.getValue();
        final ClientProfile profile = context.getUserProfile();
        final IdentityMessage message = new IdentityMessage(Session.OTRv.FOUR, senderTagValue, receiverTagValue, profile,
            ourECDHkeyPair.getPublicKey(), ourDHkeyPair.getPublicKey());
        context.setState(new StateAwaitingAuthR(ourECDHkeyPair, ourDHkeyPair, queryTag, message));
        return message;
    }
}
