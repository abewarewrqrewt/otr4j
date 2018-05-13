package net.java.otr4j.session.ake;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static net.java.otr4j.session.ake.SecurityParameters4.Component.THEIRS;
import static org.junit.Assert.*;

public class SecurityParameters4Test {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);

    private final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);

    @Test(expected = NullPointerException.class)
    public void testConstructionWithNullComponentFails() {
        new SecurityParameters4(null, ecdhKeyPair, dhKeyPair, ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionWithNullECDHKeyPairFails() {
        new SecurityParameters4(SecurityParameters4.Component.OURS, null, dhKeyPair, ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionWithNullDHKeyPairFails() {
        new SecurityParameters4(THEIRS, ecdhKeyPair, null, ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionWithNullXFails() {
        new SecurityParameters4(SecurityParameters4.Component.OURS, ecdhKeyPair, dhKeyPair, null, dhKeyPair.getPublicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionWithNullAFails() {
        new SecurityParameters4(THEIRS, ecdhKeyPair, dhKeyPair, ecdhKeyPair.getPublicKey(), null);
    }

    @Test
    public void testConstruction() {
        final Point x = ecdhKeyPair.getPublicKey();
        final BigInteger a = dhKeyPair.getPublicKey();
        final SecurityParameters4 params = new SecurityParameters4(THEIRS, ecdhKeyPair, dhKeyPair, x, a);
        assertEquals(THEIRS, params.getInitializationComponent());
        assertEquals(ecdhKeyPair, params.getEcdhKeyPair());
        assertEquals(dhKeyPair, params.getDhKeyPair());
        assertEquals(x, params.getX());
        assertEquals(a, params.getA());
    }
}
