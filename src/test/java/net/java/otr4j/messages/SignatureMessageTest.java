
package net.java.otr4j.messages;

import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.util.ByteArrays;
import org.junit.Test;

import java.security.SecureRandom;

import static java.util.Arrays.fill;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

public class SignatureMessageTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final int MAC_LENGTH_BYTES = 20;

    @Test
    public void testProtocolVerificationWorking() {
        new SignatureMessage(OTRv.THREE, new byte[0], new byte[0], SMALLEST_TAG, SMALLEST_TAG);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testProtocolVerificationVersionFourNotAllowed() {
        new SignatureMessage(OTRv.FOUR, new byte[0], new byte[0], SMALLEST_TAG, SMALLEST_TAG);
    }

    /** since this test is based on randomly generated data,
     * there is a very small chance of false positives. */
    @Test
    public void testHashCode() {
        byte[] fakeEncryptedMAC = new byte[MAC_LENGTH_BYTES];
        SignatureMessage current;
        SignatureMessage previous = null;
        for (int i = 1; i <= 10000000; i *= 10) {
            byte[] fakeEncrypted = randomBytes(RANDOM, new byte[i]);
            RANDOM.nextBytes(fakeEncryptedMAC);
            current = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, ZERO_TAG, ZERO_TAG);
            assertNotNull(current);
            assertNotEquals(current, previous);
            if (previous != null) {
                assertNotEquals(current.hashCode(), previous.hashCode());
            }
            previous = current;
        }
        for (int i = -128; i < 128; i++) {
            byte[] fakeEncrypted = new byte[100];
            fill(fakeEncrypted, (byte) i);
            fill(fakeEncryptedMAC, (byte) i);
            current = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, ZERO_TAG, ZERO_TAG);
            assertNotNull(current);
            assertNotEquals(current.hashCode(), previous.hashCode());
            previous = current;
        }
    }

    /** since this test is based on randomly generated data,
     * there is a very small chance of false positives. */
    @Test
    public void testEqualsObject() {
        final byte[] fakeEncryptedMAC = new byte[MAC_LENGTH_BYTES];
        SignatureMessage previous = null;
        for (int i = 1; i <= 10000000; i *= 10) {
            final byte[] fakeEncrypted = randomBytes(RANDOM, new byte[i]);
            RANDOM.nextBytes(fakeEncryptedMAC);
            SignatureMessage sm = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, ZERO_TAG, ZERO_TAG);
            assertNotNull(sm);
            final byte[] fakeEncrypted2 = new byte[i];
            System.arraycopy(fakeEncrypted, 0, fakeEncrypted2, 0, fakeEncrypted.length);
            final byte[] fakeEncryptedMAC2 = randomBytes(RANDOM, new byte[MAC_LENGTH_BYTES]);
            System.arraycopy(fakeEncryptedMAC, 0, fakeEncryptedMAC2, 0, fakeEncryptedMAC.length);
            SignatureMessage sm2 = new SignatureMessage(OTRv.THREE, fakeEncrypted2, fakeEncryptedMAC2, ZERO_TAG, ZERO_TAG);
            assertNotNull(sm2);
            assertEquals(sm, sm2);
            assertNotEquals(sm, previous);
            previous = sm;
        }
        for (int i = -128; i < 128; i++) {
            if (i == 0 && ByteArrays.class.desiredAssertionStatus()) {
                // Skip byte 0 as it will trigger the assertion.
                continue;
            }
            byte[] fakeEncrypted = new byte[1000];
            fill(fakeEncrypted, (byte) i);
            fill(fakeEncryptedMAC, (byte) i);
            SignatureMessage current = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, ZERO_TAG, ZERO_TAG);
            assertNotNull(current);
            assertNotEquals(current, previous);
            previous = current;
        }
    }
}
