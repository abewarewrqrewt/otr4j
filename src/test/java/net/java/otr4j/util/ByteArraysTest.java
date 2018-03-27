package net.java.otr4j.util;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.clear;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
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

    @Test(expected = NullPointerException.class)
    public void testClearNull() {
        clear(null);
    }

    @Test
    public void testClearEmptyArray() {
        clear(new byte[0]);
    }

    @Test
    public void testClearArrayOfRandomValues() {
        final byte[] empty = new byte[254];
        final byte[] r = new byte[254];
        RANDOM.nextBytes(r);
        assertFalse("Ensuring that original input is not all zeroes as that would defeat the purpose of the test.", Arrays.equals(empty, r));
        clear(r);
        assertArrayEquals(empty, r);
    }
}
