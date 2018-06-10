package net.java.otr4j.io;

import org.junit.Test;

import javax.annotation.Nonnull;

import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.io.SerializationUtils.UTF8;
import static org.bouncycastle.util.Arrays.concatenate;
import static org.junit.Assert.*;

public final class OtrEncodablesTest {

    @Test(expected = NullPointerException.class)
    public void testOtrEncodablesEncodeNull() {
        encode(null);
    }

    @Test
    public void testOtrEncodablesEncode() {
        final byte[] data = "Hello World!".getBytes(UTF8);
        final byte[] expected = concatenate(new byte[]{0x00, 0x00, 0x00, 0xc}, data);
        assertArrayEquals(expected, encode(new OtrEncodable() {
            @Override
            public void writeTo(@Nonnull final OtrOutputStream out) {
                out.writeData(data);
            }
        }));
    }
}
