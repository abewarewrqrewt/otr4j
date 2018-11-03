/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;

public class DHKeyPairsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = OtrCryptoException.class)
    public void testVerifyIllegalPublicKey() throws OtrCryptoException {
        verifyDHPublicKey(BigInteger.ONE);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyModulusConsideredIllegal() throws OtrCryptoException {
        verifyDHPublicKey(DHKeyPair.modulus());
    }

    @Test
    public void testVerifyGeneratedPublicKeySucceeds() throws OtrCryptoException {
        verifyDHPublicKey(DHKeyPair.generate(RANDOM).getPublicKey());
    }
}
