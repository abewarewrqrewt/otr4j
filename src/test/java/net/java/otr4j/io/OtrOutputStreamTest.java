package net.java.otr4j.io;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

@SuppressWarnings("ConstantConditions")
public class OtrOutputStreamTest {

    private static final ByteArrayOutputStream out = new ByteArrayOutputStream();

    @Test(expected = NullPointerException.class)
    public void testConstructNullOutputStream() {
        new OtrOutputStream(null);
    }

    @Test
    public void testConstructOtrOutputStream() {
        new OtrOutputStream(out);
    }

    @Test(expected = NullPointerException.class)
    public void testWriteNullUserProfile() throws IOException {
        final OtrOutputStream otr = new OtrOutputStream(out);
        otr.writeClientProfile(null);
    }
}
