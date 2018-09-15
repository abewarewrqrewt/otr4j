package net.java.otr4j.session.smpv4;

import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.valueOf;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static nl.dannyvanheumen.joldilocks.Ed448.basePoint;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("ConstantConditions")
public final class StateExpect4Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger a3 = valueOf(2L);
    private static final Point g3b = basePoint().multiply(valueOf(3L));
    private static final Point pa = basePoint().multiply(valueOf(4L));
    private static final Point pb = basePoint().multiply(valueOf(5L));
    private static final Point qa = basePoint().multiply(valueOf(6L));
    private static final Point qb = basePoint().multiply(valueOf(7L));

    @Test(expected = NullPointerException.class)
    public void testConstructNullSecureRandom() {
        new StateExpect4(null, a3, g3b, pa, pb, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNulla3() {
        new StateExpect4(RANDOM, null, g3b, pa, pb, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullg3b() {
        new StateExpect4(RANDOM, a3, null, pa, pb, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullpa() {
        new StateExpect4(RANDOM, a3, g3b, null, pb, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullpb() {
        new StateExpect4(RANDOM, a3, g3b, pa, null, qa, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullqa() {
        new StateExpect4(RANDOM, a3, g3b, pa, pb, null, qb);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullqb() {
        new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, null);
    }

    @Test
    public void testConstruct() {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        assertEquals(INPROGRESS, state.getStatus());
    }

    @Test(expected = NullPointerException.class)
    public void testInitiateNullContext() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        state.initiate(null, "test", valueOf(1L));
    }

    @Test(expected = SMPAbortException.class)
    public void testInitiateAbortStateExpect1() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        try {
            state.initiate(context, "test", valueOf(1L));
            fail("Expected SMP initiation to fail.");
        } catch (final SMPAbortException e) {
            verify(context).setState(any(StateExpect1.class));
            throw e;
        }
    }

    @Test
    public void testRespondWithSecret() {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        assertNull(state.respondWithSecret(null, null, null));
    }

    @Test(expected = SMPAbortException.class)
    public void testProcessNullMessage() throws SMPAbortException {
        final StateExpect4 state = new StateExpect4(RANDOM, a3, g3b, pa, pb, qa, qb);
        final SMPContext context = mock(SMPContext.class);
        state.process(context, null);
    }
}