/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static net.java.otr4j.crypto.DHKeyPair.checkPublicKey;

/**
 * Utility class for DHKeyPair instances.
 */
public final class DHKeyPairs {

    private DHKeyPairs() {
        // No need to instantiate utility class.
    }

    /**
     * Verify Diffie-Hellman public key. (For 3072 bit keys as defined in OTRv4.)
     *
     * @param publicKey The DH public key.
     * @throws OtrCryptoException For invalid DH public keys.
     */
    public static void verifyDHPublicKey(@Nonnull final BigInteger publicKey) throws OtrCryptoException {
        if (!checkPublicKey(publicKey)) {
            throw new OtrCryptoException("Invalid DH public key.");
        }
    }
}
