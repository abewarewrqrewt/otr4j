/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto.ed448;

import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.ECDHKeyPair.generate;
import static net.java.otr4j.crypto.ed448.Ed448.identity;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@SuppressWarnings("ConstantConditions")
public class ECDHKeyPairTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Scalar sk = fromBigInteger(new BigInteger("201813413369092340303433879563900627958148970380718420601528361290790948759469372234812322817714647596845093618167700052967566766936416", 10));

    @Test(expected = NullPointerException.class)
    public void testGenerateNullSecureRandom() {
        generate((SecureRandom) null);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateNullBytes() {
        generate((byte[]) null);
    }

    @Test
    public void testGenerateKeyPair() {
        final ECDHKeyPair keypair = generate(RANDOM);
        assertNotNull(keypair);
        assertNotNull(keypair.getPublicKey());
    }

    @Test
    public void testPublicKeyRegeneratable() {
        final ECDHKeyPair keypair = generate(RANDOM);
        final Point expected = keypair.getPublicKey();
        final Point generated = multiplyByBase(keypair.getSecretKey());
        assertEquals(expected, generated);
    }

    @Test
    public void testGetSecretKey() {
        final ECDHKeyPair keypair = new ECDHKeyPair(sk);
        assertEquals(sk, keypair.getSecretKey());
    }

    @Test
    public void testSharedSecretIsSymmetric() throws ValidationException {
        final ECDHKeyPair keypair1 = ECDHKeyPair.generate(RANDOM);
        final ECDHKeyPair keypair2 = ECDHKeyPair.generate(RANDOM);
        final Point shared1 = keypair1.generateSharedSecret(keypair2.getPublicKey());
        final Point shared2 = keypair2.generateSharedSecret(keypair1.getPublicKey());
        assertEquals(shared1, shared2);
    }

    @Test(expected = ValidationException.class)
    public void testSharedSecretDoesNotAcceptIdentity() throws ValidationException {
        final ECDHKeyPair keypair1 = ECDHKeyPair.generate(RANDOM);
        keypair1.generateSharedSecret(identity());
    }

    // FIXME figure out what the deal is with this contributary behavior and how to trigger this as a unit test
    @Ignore("We should be able to create circumstances where other point has small contribution and a ValidationException results. So far, I haven't been able to.")
    @Test(expected = ValidationException.class)
    public void testSharedSecretWithIllegalPoint() throws ValidationException {
        final byte[] otherScalar = randomBytes(RANDOM, new byte[57]);
        otherScalar[0] |= 0b00000011;
        otherScalar[56] = 0;
        otherScalar[55] |= 0b10000000;
        final Point other = multiplyByBase(Scalar.decodeScalar(otherScalar));
        final ECDHKeyPair keypair = ECDHKeyPair.generate(RANDOM);
        keypair.generateSharedSecret(other);
    }
}
