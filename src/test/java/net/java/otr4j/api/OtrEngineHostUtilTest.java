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

import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for OtrEngineHostUtil utilities.
 *
 * @author Danny van Heumen
 */
public class OtrEngineHostUtilTest {

    private Level originalLoggingLevel;

    @Before
    public void setUp() {
        final Logger logger = Logger.getLogger("net.java.otr4j");
        originalLoggingLevel = logger.getLevel();
        logger.setLevel(Level.OFF);
    }

    @After
    public void tearDown() {
        Logger.getLogger("net.java.otr4j").setLevel(originalLoggingLevel);
    }

    @Test
    public void testMultipleInstancesDetectedOnGoodHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.multipleInstancesDetected(host, sessionID);
        verify(host).multipleInstancesDetected(sessionID);
    }

    @Test
    public void testMultipleInstancesDetectedOnFaultyHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).multipleInstancesDetected(sessionID);
        OtrEngineHostUtil.multipleInstancesDetected(host, sessionID);
        verify(host).multipleInstancesDetected(sessionID);
    }

    @Test
    public void testMessageFromAnotherInstanceReceivedOnGoodHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.messageFromAnotherInstanceReceived(host, sessionID);
        verify(host).messageFromAnotherInstanceReceived(sessionID);
    }

    @Test
    public void testMessageFromAnotherInstanceReceivedOnFaultyHost() {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).messageFromAnotherInstanceReceived(sessionID);
        OtrEngineHostUtil.messageFromAnotherInstanceReceived(host, sessionID);
        verify(host).messageFromAnotherInstanceReceived(sessionID);
    }

    @Test
    public void testUnencryptedMessageReceivedOnGoodHost() throws OtrException {
        final String msg = "Unencrypted message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.unencryptedMessageReceived(host, sessionID, msg);
        verify(host).unencryptedMessageReceived(sessionID, msg);
    }

    @Test
    public void testUnencryptedMessageReceivedOnFaultyHost() throws OtrException {
        final String msg = "Unencrypted message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).unencryptedMessageReceived(sessionID, msg);
        OtrEngineHostUtil.unencryptedMessageReceived(host, sessionID, msg);
        verify(host).unencryptedMessageReceived(sessionID, msg);
    }

    @Test
    public void testUnreadableMessageReceivedOnGoodHost() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.unreadableMessageReceived(host, sessionID);
        verify(host).unreadableMessageReceived(sessionID);
    }

    @Test
    public void testUnreadableMessageReceivedOnFaultyHost() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).unreadableMessageReceived(sessionID);
        OtrEngineHostUtil.unreadableMessageReceived(host, sessionID);
        verify(host).unreadableMessageReceived(sessionID);
    }

    @Test
    public void testGetFallbackMessageOnGoodHost() throws OtrException {
        final String fallbackMessage = "Hey dude, get OTR to talk to me!";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getFallbackMessage(sessionID)).thenReturn(fallbackMessage);
        assertEquals(fallbackMessage, OtrEngineHostUtil.getFallbackMessage(host, sessionID));
        verify(host).getFallbackMessage(sessionID);
    }

    @Test
    public void testGetFallbackMessageOnFaultyHost() throws OtrException {
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getFallbackMessage(sessionID)).thenReturn("Hey dude, get OTR to talk to me!");
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).getFallbackMessage(sessionID);
        assertNull(OtrEngineHostUtil.getFallbackMessage(host, sessionID));
        verify(host).getFallbackMessage(sessionID);
    }

    @Test
    public void testShowErrorOnGoodHost() throws OtrException {
        final String error = "My error message.";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.showError(host, sessionID, error);
        verify(host).showError(sessionID, error);
    }

    @Test
    public void testShowErrorOnFaultyHost() throws OtrException {
        final String error = "My error message.";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).showError(sessionID, error);
        OtrEngineHostUtil.showError(host, sessionID, error);
        verify(host).showError(sessionID, error);
    }

    @Test
    public void testFinishedSessionMessageOnGoodHost() throws OtrException {
        final String msg = "My session finished message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.finishedSessionMessage(host, sessionID, msg);
        verify(host).finishedSessionMessage(sessionID, msg);
    }

    @Test
    public void testFinishedSessionMessageOnFaultyHost() throws OtrException {
        final String msg = "My session finished message";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).finishedSessionMessage(sessionID, msg);
        OtrEngineHostUtil.finishedSessionMessage(host, sessionID, msg);
        verify(host).finishedSessionMessage(sessionID, msg);
    }

    @Test
    public void testRequireEncryptedMessageOnGoodHost() throws OtrException {
        final String msg = "I require encryption";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        OtrEngineHostUtil.requireEncryptedMessage(host, sessionID, msg);
        verify(host).requireEncryptedMessage(sessionID, msg);
    }

    @Test
    public void testRequireEncryptedMessageOnFaultyHost() throws OtrException {
        final String msg = "I require encryption";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).requireEncryptedMessage(sessionID, msg);
        OtrEngineHostUtil.requireEncryptedMessage(host, sessionID, msg);
        verify(host).requireEncryptedMessage(sessionID, msg);
    }

    @Test
    public void testGetReplyForUnreadableMessageOnGoodHost() throws OtrException {
        final String replyMsg = "Hey dude, I can't ready you're message!";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getReplyForUnreadableMessage(sessionID)).thenReturn(replyMsg);
        assertEquals(replyMsg, OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionID, "default message"));
        verify(host).getReplyForUnreadableMessage(sessionID);
    }

    @Test
    public void testGetReplyForUnreadableMessageOnFaultyHost() throws OtrException {
        final String defaultMessage = "This message cannot be read.";
        final SessionID sessionID = new SessionID(null, null, null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).getReplyForUnreadableMessage(sessionID);
        assertEquals(defaultMessage, OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionID, defaultMessage));
        verify(host).getReplyForUnreadableMessage(sessionID);
    }

    @Test
    public void testExtraSymmetricKeyDiscoveredOnFaultyHost() throws OtrException {
        final String message = "My message.";
        final SessionID sessionID = new SessionID(null, null, null);
        final byte[] key = "MyPassW0rd".getBytes(US_ASCII);
        final byte[] tlvData = "Use in file transfer!".getBytes(UTF_8);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        doThrow(new IllegalArgumentException("programming error occurred")).when(host).getReplyForUnreadableMessage(sessionID);
        OtrEngineHostUtil.extraSymmetricKeyDiscovered(host, sessionID, message, key, tlvData);
        verify(host).extraSymmetricKeyDiscovered(sessionID, message, key, tlvData);
    }
}
