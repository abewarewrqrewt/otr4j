/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Collections;

import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for OtrSessionManager.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public class OtrSessionManagerTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final EdDSAKeyPair EDDSA_KEY_PAIR = EdDSAKeyPair.generate(RANDOM);
    private static final Point PUBLIC_KEY = ECDHKeyPair.generate(RANDOM).getPublicKey();
    private static final DSAKeyPair DSA_KEY_PAIR = DSAKeyPair.generateDSAKeyPair();
    private static final ClientProfile PROFILE = new ClientProfile(SMALLEST_TAG, EDDSA_KEY_PAIR.getPublicKey(), PUBLIC_KEY,
            Collections.singleton(OTRv.FOUR), Long.MAX_VALUE / 1000, DSA_KEY_PAIR.getPublic());

    @Test
    public void testGetSession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getInstanceTag(any(SessionID.class))).thenReturn(SMALLEST_TAG);
        when(host.getLocalKeyPair(any(SessionID.class))).thenReturn(DSA_KEY_PAIR);
        when(host.getLongTermKeyPair(any(SessionID.class))).thenReturn(EDDSA_KEY_PAIR);
        when(host.getClientProfile(any(SessionID.class))).thenReturn(PROFILE);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        final SessionID sid = new SessionID("user", "dude", "xmpp");
        final Session first = mgr.getSession(sid);
        assertNotNull(first);
        assertEquals(sid, first.getSessionID());
        final Session second = mgr.getSession(sid);
        assertSame(first, second);
    }

    @Test(expected = NullPointerException.class)
    public void testGetNullSession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.getSession(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetEmptySession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.getSession(SessionID.EMPTY);
    }

    @Test(expected = NullPointerException.class)
    public void testAddNullListener() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.addOtrEngineListener(null);
    }

    @Test
    public void testAddValidListener() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        final OtrEngineListener l = mock(OtrEngineListener.class);
        mgr.addOtrEngineListener(l);
    }

    @Test(expected = NullPointerException.class)
    public void testRemoveNullListener() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.removeOtrEngineListener(null);
    }

    @Test
    public void testRemoveValidListener() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        final OtrEngineListener l = mock(OtrEngineListener.class);
        mgr.removeOtrEngineListener(l);
    }
}
