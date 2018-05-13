package net.java.otr4j.crypto;

import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.DHKeyPairs.verifyPublicKey;

public class DHKeyPairsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = OtrCryptoException.class)
    public void testVerifyIllegalPublicKey() throws OtrCryptoException {
        verifyPublicKey(BigInteger.ONE);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyModulusConsideredIllegal() throws OtrCryptoException {
        verifyPublicKey(DHKeyPair.modulus());
    }

    @Test
    public void testVerifyGeneratedPublicKeySucceeds() throws OtrCryptoException {
        verifyPublicKey(DHKeyPair.generate(RANDOM).getPublicKey());
    }
}
