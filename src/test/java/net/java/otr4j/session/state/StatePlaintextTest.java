/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class StatePlaintextTest {

    private final SessionID sessionId = new SessionID("local", "remote", "xmpp");

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithViablePolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage("?OTRv234?",
                new HashSet<>(Arrays.asList(OTRv.TWO, OTRv.THREE, OTRv.FOUR)),
                "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv2OnlyPolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage("?OTRv2?",
                Collections.singleton(OTRv.TWO), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithOTRv3OnlyPolicy() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage("?OTRv3?",
                Collections.singleton(OTRv.THREE), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3 | OtrPolicy.SEND_WHITESPACE_TAG);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, atLeastOnce()).setOfferStatusSent();
    }

    @Test
    public void testTransformSendingEmbedWhitespaceTagWithNonViablePolicy() throws OtrException {
        final Logger logger = Logger.getLogger(OtrPolicy.class.getName());
        final Level original = logger.getLevel();
        try {
            logger.setLevel(Level.OFF);
            final PlainTextMessage expected = new PlainTextMessage("?OTRv?",
                Collections.<Integer>emptySet(), "Hello world!");
            final StatePlaintext state = new StatePlaintext(sessionId);
            final Context context = mock(Context.class);
            final OtrPolicy policy = new OtrPolicy(OtrPolicy.SEND_WHITESPACE_TAG);
            when(context.getSessionPolicy()).thenReturn(policy);
            when(context.getOfferStatus()).thenReturn(OfferStatus.IDLE);
            final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
            assertEquals(expected, m);
            verify(context, never()).setOfferStatusSent();
        } finally {
            logger.setLevel(original);
        }
    }

    @Test
    public void testTransformDoNotSendWhitespaceTag() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage("?OTRv?",
                Collections.<Integer>emptySet(), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.IDLE);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }

    @Test
    public void testTransformAlreadySentWhitespaceTag() throws OtrException {
        final PlainTextMessage expected = new PlainTextMessage("?OTRv?",Collections.<Integer>emptySet(), "Hello world!");
        final StatePlaintext state = new StatePlaintext(sessionId);
        final Context context = mock(Context.class);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.getOfferStatus()).thenReturn(OfferStatus.REJECTED);
        final Message m = state.transformSending(context, "Hello world!", Collections.<TLV>emptyList());
        assertEquals(expected, m);
        verify(context, never()).setOfferStatusSent();
    }
}
