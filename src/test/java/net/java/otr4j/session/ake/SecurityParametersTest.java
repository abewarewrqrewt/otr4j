package net.java.otr4j.session.ake;

import net.java.otr4j.crypto.DHKeyPairJ;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.crypto.SharedSecretTestUtil;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.crypto.OtrCryptoEngine.generateDHKeyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;

@SuppressWarnings("ConstantConditions")
public class SecurityParametersTest {
    
    private static final SecureRandom RANDOM = new SecureRandom();

    public SecurityParametersTest() {
    }

    @Test
    public void testConstruction() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairJ localDHKeyPair = generateDHKeyPair(RANDOM);
        final DHKeyPairJ remoteDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        final SecurityParameters params = new SecurityParameters(3, localDHKeyPair, remoteLongTermPublicKey,
                remoteDHKeyPair.getPublic(), s);
        assertSame(s, params.getS());
        assertSame(localDHKeyPair, params.getLocalDHKeyPair());
        assertSame(remoteDHKeyPair.getPublic(), params.getRemoteDHPublicKey());
        assertSame(remoteLongTermPublicKey, params.getRemoteLongTermPublicKey());
        assertEquals(3, params.getVersion());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalVersion() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairJ localDHKeyPair = generateDHKeyPair(RANDOM);
        final DHKeyPairJ remoteDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(1, localDHKeyPair, remoteLongTermPublicKey, remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionNegativeVersion() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairJ localDHKeyPair = generateDHKeyPair(RANDOM);
        final DHKeyPairJ remoteDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(-1, localDHKeyPair, remoteLongTermPublicKey, remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullLocalDHKeyPair() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairJ remoteDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(3, null, remoteLongTermPublicKey, remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullRemoteLongTermPublicKey() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairJ localDHKeyPair = generateDHKeyPair(RANDOM);
        final DHKeyPairJ remoteDHKeyPair = generateDHKeyPair(RANDOM);
        new SecurityParameters(3, localDHKeyPair, null, remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullRemoteDHPublicKey() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairJ localDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(3, localDHKeyPair, remoteLongTermPublicKey, null, s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullSharedSecret() {
        final DHKeyPairJ localDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        final DHKeyPairJ remoteDHKeyPair = generateDHKeyPair(RANDOM);
        new SecurityParameters(3, localDHKeyPair, remoteLongTermPublicKey, remoteDHKeyPair.getPublic(), null);
    }
}
