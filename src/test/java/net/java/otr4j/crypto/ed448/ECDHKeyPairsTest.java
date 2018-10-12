package net.java.otr4j.crypto.ed448;

import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.ValidationException;
import nl.dannyvanheumen.joldilocks.Points;
import org.junit.Test;

import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.ECDHKeyPairs.verifyECDHPublicKey;

@SuppressWarnings("ConstantConditions")
public class ECDHKeyPairsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testVerifyECDHPublicKeyNullPoint() throws ValidationException {
        verifyECDHPublicKey(null);
    }

    @Test(expected = ValidationException.class)
    public void testVerifyECDHPublicKeyIdentity() throws ValidationException {
        verifyECDHPublicKey(Points.identity());
    }

    @Test
    public void testVerifyECDHPublicKey() throws ValidationException {
        final ECDHKeyPair keypair = ECDHKeyPair.generate(RANDOM);
        verifyECDHPublicKey(keypair.getPublicKey());
    }
}
