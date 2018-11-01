package net.java.otr4j.crypto;

import net.java.otr4j.crypto.DSAKeyPair.DSASignature;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.crypto.DSAKeyPair.createDSAPublicKey;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.crypto.DSAKeyPair.verifySignature;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

@SuppressWarnings("ConstantConditions")
public final class DSAKeyPairTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DSAKeyPair DSA_KEYPAIR = generateDSAKeyPair();

    @Test
    public void testGenerateDSAKeyPair() {
        final DSAKeyPair keypair = generateDSAKeyPair();
        assertNotNull(keypair);
        assertNotNull(keypair.getPublic());
    }

    @Test(expected = NullPointerException.class)
    public void testSignRSNullMessage() {
        DSA_KEYPAIR.signRS(null);
    }

    @Test
    public void testSignRS() throws OtrCryptoException {
        final byte[] m = "hello".getBytes(UTF_8);
        final DSASignature sig = DSA_KEYPAIR.signRS(m);
        verifySignature(m, DSA_KEYPAIR.getPublic(), sig.r, sig.s);
    }

    @Test(expected = NullPointerException.class)
    public void testSignNullMessage() {
        final DSAKeyPair keypair = generateDSAKeyPair();
        keypair.sign(null);
    }

    @Test
    public void testSignMessage() throws OtrCryptoException {
        final byte[] data = randomBytes(RANDOM, new byte[RANDOM.nextInt(1000)]);
        final DSAKeyPair keypair = generateDSAKeyPair();
        final byte[] signature = keypair.sign(data);
        DSAKeyPair.verifySignature(data, keypair.getPublic(), signature);
    }

    @Test
    public void testSignRSEmptyMessage() throws OtrCryptoException {
        assumeTrue("This test can only be successful without assertions, due to safety checks.",
                !OtrCryptoEngine.class.desiredAssertionStatus());
        final byte[] m = new byte[0];
        final DSASignature sig = DSA_KEYPAIR.signRS(m);
        verifySignature(m, DSA_KEYPAIR.getPublic(), sig.r, sig.s);
    }

    @Test
    public void testGenerateDSAKeyPairDifferentKeyPairs() {
        final DSAKeyPair keypair1 = generateDSAKeyPair();
        final DSAKeyPair keypair2 = generateDSAKeyPair();
        final DSAKeyPair keypair3 = generateDSAKeyPair();
        assertNotEquals(keypair1.getPublic().getY(), keypair2.getPublic().getY());
        assertNotEquals(keypair1.getPublic().getY(), keypair3.getPublic().getY());
        assertNotEquals(keypair2.getPublic().getY(), keypair3.getPublic().getY());
        assertNotEquals(keypair1, keypair2);
        assertNotEquals(keypair1, keypair3);
        assertNotEquals(keypair2, keypair3);
    }

    @Test
    public void testRecreateDSAPublicKey() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(keypair.getPublic().getY(), params.getP(), params.getQ(), params.getG());
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = RuntimeException.class)
    public void testRecreateDSAPublicKeyNullY() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(null, params.getP(), params.getQ(), params.getG());
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = RuntimeException.class)
    public void testRecreateDSAPublicKeyNullP() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(keypair.getPublic().getY(), null, params.getQ(), params.getG());
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = RuntimeException.class)
    public void testRecreateDSAPublicKeyNullQ() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(keypair.getPublic().getY(), params.getP(), null, params.getG());
        assertEquals(keypair.getPublic(), recreated);
    }

    @Test(expected = RuntimeException.class)
    public void testRecreateDSAPublicKeyNullG() throws OtrCryptoException {
        final DSAKeyPair keypair = generateDSAKeyPair();
        final DSAParams params = keypair.getPublic().getParams();
        final DSAPublicKey recreated = createDSAPublicKey(keypair.getPublic().getY(), params.getP(), params.getQ(), null);
        assertEquals(keypair.getPublic(), recreated);
    }
}