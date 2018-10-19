package net.java.otr4j.crypto.ed448;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static net.java.otr4j.crypto.ed448.Scalar.ONE;
import static net.java.otr4j.crypto.ed448.Scalar.SCALAR_LENGTH_BYTES;
import static net.java.otr4j.crypto.ed448.Scalar.ZERO;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.bouncycastle.util.Arrays.reverse;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

// FIXME write tests to evaluate that equals does correct equality (given constantTimeEquals)
@SuppressWarnings( {"ConstantConditions", "EqualsWithItself"})
public final class ScalarTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Scalar Q_SCALAR = primeOrder();

    private static final BigInteger Q_BIGINT = Q_SCALAR.toBigInteger();

    @Test(expected = NullPointerException.class)
    public void testConstructNull() {
        new Scalar(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructValueTooSmall() {
        new Scalar(new byte[56]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructValueTooLarge() {
        new Scalar(new byte[58]);
    }

    @Test
    public void testConstruct() {
        final Scalar scalar = new Scalar(new byte[57]);
        assertArrayEquals(ZERO.encode(), scalar.encode());
    }

    @Test
    public void testProcessZeroScalar() {
        assertArrayEquals(ONE.encode(), ZERO.add(ONE).encode());
        assertArrayEquals(ZERO.encode(), ZERO.multiply(ONE).encode());
        assertArrayEquals(ONE.encode(), ONE.subtract(ZERO).encode());
        assertArrayEquals(ZERO.encode(), ZERO.mod(ONE).encode());
        assertArrayEquals(ZERO.encode(), ZERO.negate().encode());
        assertEquals(BigInteger.ZERO, ZERO.toBigInteger());
        assertArrayEquals(new byte[SCALAR_LENGTH_BYTES], ZERO.encode());
    }

    @Test
    public void testProcessOneScalar() {
        assertArrayEquals(ONE.encode(), ONE.add(ZERO).encode());
        assertArrayEquals(ONE.encode(), ONE.multiply(ONE).encode());
        assertArrayEquals(ONE.encode(), ONE.subtract(ZERO).encode());
        assertArrayEquals(ZERO.encode(), ONE.mod(ONE).encode());
        assertEquals(BigInteger.ONE, ONE.toBigInteger());
    }

    @Test
    public void testNegateScalar() {
        final byte[] data1 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value1 = new BigInteger(1, data1).mod(Q_BIGINT);
        final Scalar scalar1 = fromBigInteger(value1);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1.negate().mod(Q_BIGINT))),
                scalar1.negate().mod(Q_SCALAR).encode());
    }

    @Test
    public void testDecodeRandomScalarModQ() {
        final byte[] bytes = randomBytes(RANDOM, new byte[57]);
        final Scalar scalar = Scalar.decodeScalar(bytes);
        final BigInteger value = new BigInteger(1, reverse(bytes)).mod(Q_BIGINT);
        assertEquals(value, scalar.toBigInteger());
    }

    @Test
    public void testDoubleNegation() {
        final Scalar scalar = Scalar.decodeScalar(randomBytes(RANDOM, new byte[57]));
        assertArrayEquals(scalar.encode(), scalar.negate().negate().encode());
    }

    @Test
    public void testAddScalars() {
        // Prepare scalar value 1
        final byte[] data1 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value1 = new BigInteger(1, data1).mod(Q_BIGINT);
        final Scalar scalar1 = fromBigInteger(value1);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1)), scalar1.encode());
        // Prepare scalar value 2
        final byte[] data2 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value2 = new BigInteger(1, data2).mod(Q_BIGINT);
        final Scalar scalar2 = fromBigInteger(value2);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value2)), scalar2.encode());
        // Evaluate scalar addition
        assertArrayEquals(
                reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1.add(value2).mod(Q_BIGINT))),
                scalar1.add(scalar2).mod(Q_SCALAR).encode());
    }

    @Test
    public void testSubtractScalars() {
        // Prepare scalar value 1
        final byte[] data1 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value1 = new BigInteger(1, data1).mod(Q_BIGINT);
        final Scalar scalar1 = fromBigInteger(value1);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1)), scalar1.encode());
        // Prepare scalar value 2
        final byte[] data2 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value2 = new BigInteger(1, data2).mod(Q_BIGINT);
        final Scalar scalar2 = fromBigInteger(value2);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value2)), scalar2.encode());
        // Evaluate scalar addition
        assertArrayEquals(
                reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1.subtract(value2).mod(Q_BIGINT))),
                scalar1.subtract(scalar2).mod(Q_SCALAR).encode());
    }

    @Test
    public void testMultiplyScalars() {
        // Prepare scalar value 1
        final byte[] data1 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value1 = new BigInteger(1, data1).mod(Q_BIGINT);
        final Scalar scalar1 = fromBigInteger(value1);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1)), scalar1.encode());
        // Prepare scalar value 2
        final byte[] data2 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value2 = new BigInteger(1, data2).mod(Q_BIGINT);
        final Scalar scalar2 = fromBigInteger(value2);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value2)), scalar2.encode());
        // Evaluate scalar addition
        assertArrayEquals(
                reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1.subtract(value2).mod(Q_BIGINT))),
                scalar1.subtract(scalar2).mod(Q_SCALAR).encode());
    }

    @Test
    public void testScalarModulo() {
        assertArrayEquals(ZERO.encode(), decodeScalar(new byte[]{8}).mod(decodeScalar(new byte[]{4})).encode());
    }

    @Test
    public void testScalarModuloQ() {
        assertArrayEquals(ZERO.encode(), Q_SCALAR.mod(Q_SCALAR).encode());
    }

    @Test
    public void testScalarModuloRandom() {
        // bytes intentionally chosen smaller such that `mod q` does not come into effect
        final byte[] valueBytes = randomBytes(RANDOM, new byte[20]);
        final byte[] modulusBytes = randomBytes(RANDOM, new byte[20]);
        final BigInteger bigIntResult = new BigInteger(1, reverse(valueBytes)).mod(new BigInteger(1,
                reverse(modulusBytes)));
        final Scalar scalarResult = decodeScalar(valueBytes).mod(decodeScalar(modulusBytes));
        assertEquals(bigIntResult, scalarResult.toBigInteger());
    }

    @Test
    public void testScalarComparison() {
        assertEquals(1, ONE.compareTo(ZERO));
        assertEquals(-1, ZERO.compareTo(ONE));
        assertEquals(0, ONE.compareTo(ONE));
    }

    @Test
    public void testScalarComparisonEqual() {
        final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
        assertEquals(0, scalar.compareTo(scalar));
    }

    @Test
    public void testScalarRandomComparison() {
        final byte[] valueBytes1 = randomBytes(RANDOM, new byte[57]);
        final byte[] valueBytes2 = randomBytes(RANDOM, new byte[57]);
        final Scalar scalar1 = decodeScalar(valueBytes1);
        final Scalar scalar2 = decodeScalar(valueBytes2);
        final BigInteger integer1 = new BigInteger(1, reverse(valueBytes1)).mod(Q_BIGINT);
        final BigInteger integer2 = new BigInteger(1, reverse(valueBytes2)).mod(Q_BIGINT);
        assertEquals(integer1.compareTo(integer2), scalar1.compareTo(scalar2));
    }

    @Test
    public void testEncodeTo() {
        final byte[] bytes = randomBytes(RANDOM, new byte[57]);
        bytes[55] = bytes[56] = 0;
        final Scalar scalar = decodeScalar(bytes);
        final byte[] encoded = new byte[57];
        scalar.encodeTo(encoded, 0);
        assertArrayEquals(bytes, encoded);
    }

    @Test
    public void testEncodeToOffset() {
        final byte[] bytes = randomBytes(RANDOM, new byte[57]);
        bytes[55] = bytes[56] = 0;
        final Scalar scalar = decodeScalar(bytes);
        final byte[] encoded = new byte[59];
        scalar.encodeTo(encoded, 2);
        final byte[] expected = new byte[59];
        System.arraycopy(bytes, 0, expected, 2, bytes.length);
        assertArrayEquals(expected, encoded);
    }

    @Test
    public void testEncodeToByteArrayOutputStream() throws IOException {
        final byte[] bytes = randomBytes(RANDOM, new byte[57]);
        bytes[55] = bytes[56] = 0;
        final Scalar scalar = decodeScalar(bytes);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        scalar.encodeTo(out);
        assertArrayEquals(bytes, out.toByteArray());
    }
}