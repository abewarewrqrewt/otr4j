package net.java.otr4j.crypto.ed448;

import nl.dannyvanheumen.joldilocks.Ed448;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.Arrays.reverse;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * Scalar representation for Ed448 operations.
 *
 * The scalar implementation is currently very inefficient as it converts to BigInteger and back in order to perform the
 * arithmetic operations, but it does have the benefit that the current bad implementation is isolated to the innermost
 * implementation details.
 */
// FIXME implement arithmetic operations that operate directly on byte-arrays.
// FIXME implement Closeable interface and ensure correct cleaning of internal byte-array representing scalar value.
public final class Scalar implements Comparable<Scalar> {

    /**
     * Length of scalar byte-representation in bytes.
     */
    public static final int SCALAR_LENGTH_BYTES = 57;

    /**
     * Scalar value representing zero.
     */
    public static final Scalar ZERO = new Scalar(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

    /**
     * Scalar value representing one.
     */
    public static final Scalar ONE = new Scalar(new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

    private final byte[] encoded;

    @Nonnull
    Scalar(@Nonnull final byte[] encoded) {
        this.encoded = requireLengthExactly(SCALAR_LENGTH_BYTES, encoded);
    }

    /**
     * Decode scalar from byte representation.
     *
     * @param encoded encoded scalar value
     * @return Returns scalar instance.
     */
    // FIXME verify that indeed all decoded scalars must be executed `mod q`. Most likely true.
    // TODO NOTE: decodeScalar now also ensures `mod q`. Ensure that optimized implementation provide an alternative for this, even if implemented outside of `decodeScalar`.
    @Nonnull
    public static Scalar decodeScalar(@Nonnull final byte[] encoded) {
        return fromBigInteger(new BigInteger(1, reverse(encoded)));
    }

    /**
     * Construct scalar from big integer value.
     *
     * @param value the value in BigInteger representation
     * @return Returns scalar instance.
     */
    @Nonnull
    public static Scalar fromBigInteger(@Nonnull final BigInteger value) {
        return new Scalar(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value.mod(Ed448.primeOrder()))));
    }

    /**
     * Negate scalar value.
     *
     * @return Returns negated scalar value.
     */
    @Nonnull
    public Scalar negate() {
        return fromBigInteger(toBigInteger().negate());
    }

    /**
     * Multiple scalar with provided scalar.
     *
     * @param scalar the multiplicant
     * @return Returns the multiplication result.
     */
    @Nonnull
    public Scalar multiply(@Nonnull final Scalar scalar) {
        return fromBigInteger(toBigInteger().multiply(scalar.toBigInteger()));
    }

    /**
     * Add provided scalar to scalar.
     *
     * @param scalar the scalar to be added
     * @return Returns the addition result.
     */
    @Nonnull
    public Scalar add(@Nonnull final Scalar scalar) {
        return fromBigInteger(toBigInteger().add(scalar.toBigInteger()));
    }

    /**
     * Subtract provided scalar from scalar.
     *
     * @param scalar the scalar to be subtracted
     * @return Returns the subtraction result.
     */
    @Nonnull
    public Scalar subtract(@Nonnull final Scalar scalar) {
        return fromBigInteger(toBigInteger().subtract(scalar.toBigInteger()));
    }

    /**
     * Modulo operation on scalar.
     *
     * @param modulus the modulus
     * @return Returns result of modulo.
     */
    @Nonnull
    public Scalar mod(@Nonnull final Scalar modulus) {
        return fromBigInteger(toBigInteger().mod(modulus.toBigInteger()));
    }

    /**
     * Encode scalar value to byte-representation.
     *
     * @return Byte-representation of scalar value.
     */
    // FIXME duplicating memory but should it be cleaned?
    @Nonnull
    public byte[] encode() {
        return this.encoded.clone();
    }

    /**
     * Encode scalar value to byte-representation to provided destination.
     *
     * @param dst    the destination for the encoded value
     * @param offset the offset for the starting point to writing the encoded value
     */
    public void encodeTo(@Nonnull final byte[] dst, final int offset) {
        System.arraycopy(this.encoded, 0, dst, offset, SCALAR_LENGTH_BYTES);
    }

    /**
     * Encode scalar value to byte-representation and write to OutputStream.
     *
     * @param out the destination
     * @throws IOException In case of failure in OutputStream during writing.
     */
    public void encodeTo(@Nonnull final OutputStream out) throws IOException {
        out.write(this.encoded, 0, SCALAR_LENGTH_BYTES);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Scalar scalar = (Scalar) o;
        return constantTimeEquals(this.encoded, scalar.encoded);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.encoded);
    }

    // TODO make Scalar.compareTo perform constant-time comparison
    @Override
    public int compareTo(@Nonnull final Scalar scalar) {
        assert this.encoded.length == SCALAR_LENGTH_BYTES && scalar.encoded.length == SCALAR_LENGTH_BYTES;
        for (int i = SCALAR_LENGTH_BYTES - 1; i >= 0; --i) {
            final byte xi = (byte) (this.encoded[i] ^ Byte.MIN_VALUE);
            final byte yi = (byte) (scalar.encoded[i] ^ Byte.MIN_VALUE);
            if (xi < yi) {
                return -1;
            }
            if (xi > yi) {
                return 1;
            }
        }
        return 0;
    }

    // FIXME workaround that is necessary as long as Point cannot calculate with byte-arrays.
    @Nonnull
    BigInteger toBigInteger() {
        return new BigInteger(1, reverse(this.encoded));
    }
}
