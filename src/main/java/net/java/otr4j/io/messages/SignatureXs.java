package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.UnsupportedTypeException;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;

/**
 * Utilities for SignatureX.
 */
public final class SignatureXs {

    private SignatureXs() {
        // No need to instantiate utility class.
    }

    /**
     * Read Signature X signature data.
     *
     * @return Returns Signature X instance.
     * @throws ProtocolException        In case of failure in reading the message.
     * @throws OtrCryptoException       In case of failures while processing the message content.
     * @throws UnsupportedTypeException In case of unsupported public key type.
     */
    @Nonnull
    public static SignatureX readSignatureX(@Nonnull final byte[] bytes) throws ProtocolException, OtrCryptoException, UnsupportedTypeException {
        final OtrInputStream in = new OtrInputStream(bytes);
        final DSAPublicKey pubKey = in.readPublicKey();
        final int dhKeyID = in.readInt();
        final byte[] sig = in.readSignature(pubKey);
        return new SignatureX(pubKey, dhKeyID, sig);
    }
}
