/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.io.ErrorMessage;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import static net.java.otr4j.io.ErrorMessage.ERROR_1_MESSAGE_UNREADABLE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_UNREADABLE_MESSAGE;
import static net.java.otr4j.session.state.Contexts.signalUnreadableMessage;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings({"ConstantConditions", "unchecked"})
public final class ContextsTest {

    @Test(expected = NullPointerException.class)
    public void testSignalUnreadableMessageNullContext() throws OtrException {
        signalUnreadableMessage(null, ERROR_ID_UNREADABLE_MESSAGE, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
    }

    @Test(expected = NullPointerException.class)
    public void testSignalUnreadableMessageNullIdentifier() throws OtrException {
        final Context context = mock(Context.class);
        signalUnreadableMessage(context, null, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
    }

    @Test(expected = NullPointerException.class)
    public void testSignalUnreadableMessageNullMessage() throws OtrException {
        final Context context = mock(Context.class);
        signalUnreadableMessage(context, ERROR_ID_UNREADABLE_MESSAGE, null);
    }

    @Test
    public void testSignalUnreadableMessage() throws OtrException {
        final String message = "Hey man, I can't read that!";
        final SessionID sessionID = new SessionID("alice@network", "bob@network", "network");
        final Context context = mock(Context.class);
        when(context.getSessionID()).thenReturn(sessionID);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getReplyForUnreadableMessage(eq(sessionID), eq(ERROR_ID_UNREADABLE_MESSAGE))).thenReturn(message);
        when(context.getHost()).thenReturn(host);
        ArgumentCaptor<ErrorMessage> captor = ArgumentCaptor.forClass(ErrorMessage.class);
        signalUnreadableMessage(context, ERROR_ID_UNREADABLE_MESSAGE, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
        verify(host, times(1)).unreadableMessageReceived(eq(sessionID));
        verify(context, times(1)).injectMessage(captor.capture());
        assertEquals(message, captor.getValue().error);
    }

    @Test
    public void testSignalUnreadableMessageFallbackToDefaultMessage() throws OtrException {
        final SessionID sessionID = new SessionID("alice@network", "bob@network", "network");
        final Context context = mock(Context.class);
        when(context.getSessionID()).thenReturn(sessionID);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getReplyForUnreadableMessage(eq(sessionID), eq(ERROR_ID_UNREADABLE_MESSAGE))).thenThrow(RuntimeException.class);
        when(context.getHost()).thenReturn(host);
        ArgumentCaptor<ErrorMessage> captor = ArgumentCaptor.forClass(ErrorMessage.class);
        signalUnreadableMessage(context, ERROR_ID_UNREADABLE_MESSAGE, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
        verify(host, times(1)).unreadableMessageReceived(eq(sessionID));
        verify(context, times(1)).injectMessage(captor.capture());
        assertEquals(ERROR_ID_UNREADABLE_MESSAGE, captor.getValue().identifier);
        assertEquals(ERROR_1_MESSAGE_UNREADABLE_MESSAGE, captor.getValue().error);
    }

    @Test
    public void testSignalUnreadableMessageCanHandleBadHost() throws OtrException {
        final SessionID sessionID = new SessionID("alice@network", "bob@network", "network");
        final Context context = mock(Context.class);
        when(context.getSessionID()).thenReturn(sessionID);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getReplyForUnreadableMessage(eq(sessionID), eq(ERROR_ID_UNREADABLE_MESSAGE))).thenReturn("Cannot read message.");
        doThrow(RuntimeException.class).when(host).unreadableMessageReceived(eq(sessionID));
        when(context.getHost()).thenReturn(host);
        ArgumentCaptor<ErrorMessage> captor = ArgumentCaptor.forClass(ErrorMessage.class);
        signalUnreadableMessage(context, ERROR_ID_UNREADABLE_MESSAGE, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
        verify(host, times(1)).unreadableMessageReceived(eq(sessionID));
        verify(context, times(1)).injectMessage(captor.capture());
        assertEquals(ERROR_ID_UNREADABLE_MESSAGE, captor.getValue().identifier);
        assertEquals("Cannot read message.", captor.getValue().error);
    }

    @Test(expected = OtrException.class)
    public void testSignalUnreadableMessagePropagatesErrorsDuringInjection() throws OtrException {
        final SessionID sessionID = new SessionID("alice@network", "bob@network", "network");
        final Context context = mock(Context.class);
        when(context.getSessionID()).thenReturn(sessionID);
        doThrow(OtrException.class).when(context).injectMessage(any(ErrorMessage.class));
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getReplyForUnreadableMessage(eq(sessionID), eq(""))).thenReturn("Cannot read message.");
        when(context.getHost()).thenReturn(host);
        signalUnreadableMessage(context, "", ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
    }
}