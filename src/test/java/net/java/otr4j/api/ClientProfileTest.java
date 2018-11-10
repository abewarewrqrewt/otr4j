/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Collections;

import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.crypto.ed448.EdDSAKeyPair.generate;

@SuppressWarnings("ConstantConditions")
public final class ClientProfileTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair longTermKeyPair = generate(RANDOM);

    private final Point forgingPublicKey = generate(RANDOM).getPublicKey();

    private final DSAKeyPair dsaKeyPair = generateDSAKeyPair();

    @Test
    public void testConstructWithoutDSAPublicKey() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey, singleton(Session.Version.FOUR),
                null);
    }

    @Test
    public void testConstructWithDSAPublicKey() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey, singleton(Version.FOUR),
                dsaKeyPair.getPublic());
    }

    @Test(expected = NullPointerException.class)
    public void testConsructNullInstanceTag() {
        new ClientProfile(null, this.longTermKeyPair.getPublicKey(), forgingPublicKey, singleton(Session.Version.FOUR),
                null);
    }

    @Test(expected = NullPointerException.class)
    public void testConsructNullPublicKey() {
        new ClientProfile(SMALLEST_TAG, null, forgingPublicKey, singleton(Session.Version.FOUR),
                null);
    }

    @Test(expected = NullPointerException.class)
    public void testConsructNullForgingKey() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), null, singleton(Version.FOUR),
                null);
    }

    @Test(expected = NullPointerException.class)
    public void testConsructNullVersions() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey, null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructEmptyVersions() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey,
                Collections.<Integer>emptySet(), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIllegalVersionsList() {
        new ClientProfile(SMALLEST_TAG, this.longTermKeyPair.getPublicKey(), forgingPublicKey, singleton(Session.Version.THREE),
                null);
    }
}
