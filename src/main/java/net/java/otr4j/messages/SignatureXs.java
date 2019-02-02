/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.UnsupportedTypeException;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.crypto.DSAKeyPair.DSA_SIGNATURE_LENGTH_BYTES;

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
     * @param bytes The bytes representing a SignatureX, to be read.
     * @return Returns Signature X instance.
     * @throws ProtocolException        In case of failure in reading the message.
     * @throws OtrCryptoException       In case of failures while processing the message content.
     * @throws UnsupportedTypeException In case of unsupported public key type.
     */
    @Nonnull
    public static SignatureX readSignatureX(@Nonnull final byte[] bytes) throws ProtocolException, OtrCryptoException,
            UnsupportedTypeException {
        final OtrInputStream in = new OtrInputStream(bytes);
        final DSAPublicKey pubKey = in.readPublicKey();
        final int dhKeyID = in.readInt();
        if (dhKeyID == 0) {
            throw new ProtocolException("Illegal DH key ID encountered. Must be > 0, but was " + dhKeyID);
        }
        final byte[] sig = in.readSignature(pubKey);
        if (sig.length != DSA_SIGNATURE_LENGTH_BYTES) {
            throw new ProtocolException("Read DSA signature of invalid length. Expecting only 40 bytes signatures. (Based on 1024 bits DSA keypair.)");
        }
        return new SignatureX(pubKey, dhKeyID, sig);
    }
}
