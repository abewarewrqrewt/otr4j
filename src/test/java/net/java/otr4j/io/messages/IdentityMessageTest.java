package net.java.otr4j.io.messages;

import net.java.otr4j.profile.UserProfile;
import nl.dannyvanheumen.joldilocks.Ed448;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;

public class IdentityMessageTest {

    @Test
    public void testConstructIdentityMessage() {
        final UserProfile userProfile = new UserProfile();
        final Point y = Ed448.P;
        final BigInteger b = BigInteger.TEN;
        new IdentityMessage(4, 0, 0, userProfile, y, b);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullUserProfile() {
        final Point y = Ed448.P;
        final BigInteger b = BigInteger.TEN;
        new IdentityMessage(4, 0, 0, null, y, b);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructIdentityMessageNullY() {
        final UserProfile userProfile = new UserProfile();
        final BigInteger b = BigInteger.TEN;
        new IdentityMessage(4, 0, 0, userProfile, null, b);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructIdentityMessageNullB() {
        final UserProfile userProfile = new UserProfile();
        final Point y = Ed448.P;
        new IdentityMessage(4, 0, 0, userProfile, y, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructTooLowProtocolVersion() {
        final UserProfile userProfile = new UserProfile();
        final Point y = Ed448.P;
        final BigInteger b = BigInteger.TEN;
        new IdentityMessage(3, 0, 0, userProfile, y, b);
    }
}
