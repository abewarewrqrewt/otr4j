package net.java.otr4j.util;

import org.junit.Test;

import java.security.SecureRandom;

import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.junit.Assert.assertSame;

public class ByteArraysTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = NullPointerException.class)
    public void testRequireLengthExactlyNullArray() {
        requireLengthExactly(0, null);
    }

    @Test
    public void testRequireLengthExactlyCorrect() {
        final byte[] t = new byte[22];
        assertSame(t, requireLengthExactly(22, t));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireLengthExactlyOffByOneDown() {
        final byte[] t = new byte[22];
        requireLengthExactly(23, t);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireLengthExactlyOffByOneUp() {
        final byte[] t = new byte[22];
        requireLengthExactly(21, t);
    }
}
