package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Points;
import org.junit.Test;

import java.security.SecureRandom;

import static net.java.otr4j.crypto.ECDHKeyPairs.verifyECDHPublicKey;

@SuppressWarnings("ConstantConditions")
public class ECDHKeyPairsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testVerifyECDHPublicKeyNullPoint() throws OtrCryptoException {
        verifyECDHPublicKey(null);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyECDHPublicKeyIdentity() throws OtrCryptoException {
        verifyECDHPublicKey(Points.identity());
    }

    @Test
    public void testVerifyECDHPublicKey() throws OtrCryptoException {
        final ECDHKeyPair keypair = ECDHKeyPair.generate(RANDOM);
        verifyECDHPublicKey(keypair.getPublicKey());
    }
}
