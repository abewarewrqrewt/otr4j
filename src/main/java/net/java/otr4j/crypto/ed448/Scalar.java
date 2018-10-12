package net.java.otr4j.crypto.ed448;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static org.bouncycastle.util.Arrays.reverse;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.bouncycastle.util.BigIntegers.fromUnsignedByteArray;

/**
 * Scalar representation for Ed448 operations.
 */
public final class Scalar implements Comparable<Scalar> {

    /**
     * Length of scalar byte-representation in bytes.
     */
    private static final int SCALAR_LENGTH_BYTES = 56;

    /**
     * Scalar value representing zero.
     */
    public static final Scalar ZERO = new Scalar(BigInteger.ZERO);

    /**
     * Scalar value representing one.
     */
    public static final Scalar ONE = new Scalar(BigInteger.ONE);

    final BigInteger value;

    @Nonnull
    private Scalar(@Nonnull final BigInteger value) {
        this.value = requireNonNull(value);
    }

    /**
     * Decode scalar from byte representation.
     *
     * @param encoded encoded scalar value
     * @return Returns scalar instance.
     */
    @Nonnull
    public static Scalar decodeScalar(@Nonnull final byte[] encoded) {
        return new Scalar(fromUnsignedByteArray(reverse(encoded)));
    }

    /**
     * Construct scalar from big integer value.
     *
     * @param value the value in BigInteger representation
     * @return Returns scalar instance.
     */
    @Nonnull
    public static Scalar fromBigInteger(@Nonnull final BigInteger value) {
        return new Scalar(value);
    }

    /**
     * Negate scalar value.
     *
     * @return Returns negated scalar value.
     */
    @Nonnull
    public Scalar negate() {
        return new Scalar(this.value.negate());
    }

    /**
     * Multiple scalar with provided scalar.
     *
     * @param scalar the multiplicant
     * @return Returns the multiplication result.
     */
    @Nonnull
    public Scalar multiply(@Nonnull final Scalar scalar) {
        return new Scalar(this.value.multiply(scalar.value));
    }

    /**
     * Add provided scalar to scalar.
     *
     * @param scalar the scalar to be added
     * @return Returns the addition result.
     */
    @Nonnull
    public Scalar add(@Nonnull final Scalar scalar) {
        return new Scalar(this.value.add(scalar.value));
    }

    /**
     * Subtract provided scalar from scalar.
     *
     * @param scalar the scalar to be subtracted
     * @return Returns the subtraction result.
     */
    @Nonnull
    public Scalar subtract(@Nonnull final Scalar scalar) {
        return new Scalar(this.value.subtract(scalar.value));
    }

    /**
     * Modulo operation on scalar.
     *
     * @param modulus the modulus
     * @return Returns result of modulo.
     */
    @Nonnull
    public Scalar mod(@Nonnull final Scalar modulus) {
        return new Scalar(this.value.mod(modulus.value));
    }

    /**
     * Encode scalar value to byte-representation.
     *
     * @return Byte-representation of scalar value.
     */
    @Nonnull
    public byte[] encode() {
        return reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, this.value));
    }

    /**
     * Encode scalar value to byte-representation to provided destination.
     *
     * @param dst    the destination for the encoded value
     * @param offset the offset for the starting point to writing the encoded value
     */
    public void encodeTo(@Nonnull final byte[] dst, final int offset) {
        final byte[] encoded = this.encode();
        System.arraycopy(encoded, 0, dst, offset, SCALAR_LENGTH_BYTES);
    }

    /**
     * Encode scalar value to byte-representation and write to OutputStream.
     *
     * @param out the destination
     * @throws IOException In case of failure in OutputStream during writing.
     */
    public void encodeTo(@Nonnull final OutputStream out) throws IOException {
        final byte[] encoded = this.encode();
        out.write(encoded, 0, SCALAR_LENGTH_BYTES);
    }

    @Override
    public boolean equals(final Object o) {
        // FIXME should we make exception to detect same-instance comparison?
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Scalar scalar = (Scalar) o;
        // FIXME needs constant-time comparison!
        return Objects.equals(value, scalar.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public int compareTo(final Scalar scalar) {
        return this.value.compareTo(scalar.value);
    }
}
