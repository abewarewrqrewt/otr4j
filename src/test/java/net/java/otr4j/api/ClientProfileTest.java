package net.java.otr4j.api;

import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.Collections;

import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.ed448.EdDSAKeyPair.generate;
import static net.java.otr4j.crypto.OtrCryptoEngine.generateDSAKeyPair;

@SuppressWarnings("ConstantConditions")
public final class ClientProfileTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair longTermKeyPair = generate(RANDOM);

    private final Point forgingPublicKey = generate(RANDOM).getPublicKey();

    private final KeyPair dsaKeyPair = generateDSAKeyPair();

    @Test
    public void testConstructWithoutDSAPublicKey() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey,
                singleton(OTRv.FOUR), System.currentTimeMillis() / 1000 + 86400, null);
    }

    @Test
    public void testConstructWithDSAPublicKey() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey,
                singleton(OTRv.FOUR), System.currentTimeMillis() / 1000 + 86400,
                (DSAPublicKey) dsaKeyPair.getPublic());
    }

    @Test(expected = NullPointerException.class)
    public void testConsructNullInstanceTag() {
        new ClientProfile(null, this.longTermKeyPair.getPublicKey(), forgingPublicKey,
                singleton(OTRv.FOUR), System.currentTimeMillis() / 1000 + 86400, null);
    }

    @Test(expected = NullPointerException.class)
    public void testConsructNullPublicKey() {
        new ClientProfile(SMALLEST_TAG, null, forgingPublicKey, singleton(OTRv.FOUR),
            System.currentTimeMillis() / 1000 + 86400, null);
    }

    @Test(expected = NullPointerException.class)
    public void testConsructNullForgingKey() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), null, singleton(OTRv.FOUR),
            System.currentTimeMillis() / 1000 + 86400, null);
    }

    @Test(expected = NullPointerException.class)
    public void testConsructNullVersions() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey, null,
            System.currentTimeMillis() / 1000 + 86400, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructEmptyVersions() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey,
            Collections.<Integer>emptySet(), System.currentTimeMillis() / 1000 + 86400, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalVersionsList() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey, singleton(OTRv.THREE),
            System.currentTimeMillis() / 1000 + 86400, null);
    }
}
