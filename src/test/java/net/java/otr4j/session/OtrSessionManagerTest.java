/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import org.junit.Test;
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

    @Test
    public void testGetSession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getInstanceTag(any(SessionID.class))).thenReturn(InstanceTag.SMALLEST_TAG);
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
