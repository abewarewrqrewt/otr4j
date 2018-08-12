/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SmpEngineHostUtilTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Level originalLoggingLevel;

    @Before
    public void setUp() {
        final Logger globalLogger = Logger.getLogger(SmpEngineHostUtil.class.getName());
        this.originalLoggingLevel = globalLogger.getLevel();
        globalLogger.setLevel(Level.OFF);
    }

    @After
    public void tearDown() {
        Logger.getLogger(SmpEngineHostUtil.class.getName()).setLevel(this.originalLoggingLevel);
    }

    @Test
    public void testSmpErrorOnGoodHost() {
        final boolean cheated = true;
        final int type = 1;
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        SmpEngineHostUtil.smpError(host, sessionID, type, cheated);
        verify(host).smpError(sessionID, type, cheated);
    }

    @Test
    public void testSmpErrorOnFaultyHost() {
        final boolean cheated = true;
        final int type = 1;
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).smpError(sessionID, type, cheated);
        SmpEngineHostUtil.smpError(host, sessionID, type, cheated);
        verify(host).smpError(sessionID, type, cheated);
    }

    @Test
    public void testSmpAbortedOnGoodHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        SmpEngineHostUtil.smpAborted(host, sessionID);
        verify(host).smpAborted(sessionID);
    }

    @Test
    public void testSmpAbortedOnFaultyHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).smpAborted(sessionID);
        SmpEngineHostUtil.smpAborted(host, sessionID);
        verify(host).smpAborted(sessionID);
    }

    @Test
    public void testVerifyOnGoodHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        SmpEngineHostUtil.verify(host, sessionID, fingerprint);
        verify(host).verify(sessionID, fingerprint);
    }

    @Test
    public void testVerifyOnBadHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        doThrow(new IllegalStateException("some bad stuff happened")).when(host).verify(sessionID, fingerprint);
        SmpEngineHostUtil.verify(host, sessionID, fingerprint);
        verify(host).verify(sessionID, fingerprint);
    }

    @Test
    public void testUnverifyOnGoodHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        SmpEngineHostUtil.unverify(host, sessionID, fingerprint);
        verify(host).unverify(sessionID, fingerprint);
    }

    @Test
    public void testUnverifyOnBadHost() {
        final String fingerprint = "myfingerprint";
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        doThrow(new IllegalStateException("some bad stuff happened")).when(host).unverify(sessionID, fingerprint);
        SmpEngineHostUtil.unverify(host, sessionID, fingerprint);
        verify(host).unverify(sessionID, fingerprint);
    }

    @Test
    public void testAskForSecretOnGoodHost() {
        final String question = "What's my secret?";
        final InstanceTag sender = InstanceTag.random(RANDOM);
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        SmpEngineHostUtil.askForSecret(host, sessionID, sender, question);
        verify(host).askForSecret(sessionID, sender, question);
    }

    @Test
    public void testAskForSecretOnFaultyHost() {
        final String question = "What's my secret?";
        final InstanceTag sender = InstanceTag.random(RANDOM);
        final SessionID sessionID = new SessionID(null, null, null);
        final SmpEngineHost host = mock(SmpEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).askForSecret(sessionID, sender, question);
        SmpEngineHostUtil.askForSecret(host, sessionID, sender, question);
        verify(host).askForSecret(sessionID, sender, question);
    }
}
