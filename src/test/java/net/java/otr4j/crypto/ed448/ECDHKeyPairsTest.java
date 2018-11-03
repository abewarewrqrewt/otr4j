/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import org.junit.Test;

import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.ECDHKeyPairs.verifyECDHPublicKey;
import static net.java.otr4j.crypto.ed448.Ed448.identity;

@SuppressWarnings("ConstantConditions")
public class ECDHKeyPairsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testVerifyECDHPublicKeyNullPoint() throws ValidationException {
        verifyECDHPublicKey(null);
    }

    @Test(expected = ValidationException.class)
    public void testVerifyECDHPublicKeyIdentity() throws ValidationException {
        verifyECDHPublicKey(identity());
    }

    @Test
    public void testVerifyECDHPublicKey() throws ValidationException {
        final ECDHKeyPair keypair = ECDHKeyPair.generate(RANDOM);
        verifyECDHPublicKey(keypair.getPublicKey());
    }
}
