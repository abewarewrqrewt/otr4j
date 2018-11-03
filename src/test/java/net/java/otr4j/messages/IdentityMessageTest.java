/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfileTestUtils;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.math.BigInteger;

import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;

@SuppressWarnings("ConstantConditions")
public final class IdentityMessageTest {

    private static final ClientProfileTestUtils profileTestUtils = new ClientProfileTestUtils();

    @Test
    public void testConstructIdentityMessage() {
        final ClientProfilePayload clientProfile = profileTestUtils.createTransitionalUserProfile();
        final Point y = basePoint();
        final BigInteger b = BigInteger.TEN;
        new IdentityMessage(4, ZERO_TAG, ZERO_TAG, clientProfile, y, b);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullUserProfile() {
        final Point y = basePoint();
        final BigInteger b = BigInteger.TEN;
        new IdentityMessage(4, ZERO_TAG, ZERO_TAG, null, y, b);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructIdentityMessageNullY() {
        final ClientProfilePayload clientProfile = profileTestUtils.createUserProfile();
        final BigInteger b = BigInteger.TEN;
        new IdentityMessage(4, ZERO_TAG, ZERO_TAG, clientProfile, null, b);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructIdentityMessageNullB() {
        final ClientProfilePayload clientProfile = profileTestUtils.createUserProfile();
        final Point y = basePoint();
        new IdentityMessage(4, ZERO_TAG, ZERO_TAG, clientProfile, y, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructTooLowProtocolVersion() {
        final ClientProfilePayload clientProfile = profileTestUtils.createUserProfile();
        final Point y = basePoint();
        final BigInteger b = BigInteger.TEN;
        new IdentityMessage(3, ZERO_TAG, ZERO_TAG, clientProfile, y, b);
    }
}
