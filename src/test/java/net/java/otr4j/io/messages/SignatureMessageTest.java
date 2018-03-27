
package net.java.otr4j.io.messages;

import java.util.Arrays;
import java.util.Random;
import net.java.otr4j.io.SerializationConstants;
import net.java.otr4j.api.Session.OTRv;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class SignatureMessageTest {

    @Test
    /** since this test is based on randomly generated data,
     * there is a very small chance of false positives. */
    public void testHashCode() {
        Random r = new Random();
        byte[] fakeEncryptedMAC = new byte[SerializationConstants.TYPE_LEN_MAC];
        SignatureMessage current = null;
        SignatureMessage previous = null;
        for (int i = 1; i <= 10000000; i *= 10) {
            byte[] fakeEncrypted = new byte[i];
            r.nextBytes(fakeEncrypted);
            r.nextBytes(fakeEncryptedMAC);
            current = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, 0, 0);
            assertNotNull(current);
            assertFalse(current.equals(null));
            assertFalse(current.equals(previous));
            if (previous != null)
                assertFalse(current.hashCode() == previous.hashCode());
            previous = current;
        }
        for (int i = -128; i < 128; i++) {
            byte[] fakeEncrypted = new byte[100];
            Arrays.fill(fakeEncrypted, (byte) i);
            Arrays.fill(fakeEncryptedMAC, (byte) i);
            current = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, 0, 0);
            assertNotNull(current);
            assertFalse(current.hashCode() == previous.hashCode());
            previous = current;
        }
    }

    @Test
    /** since this test is based on randomly generated data,
     * there is a very small chance of false positives. */
    public void testEqualsObject() {
        Random r = new Random();
        byte[] fakeEncryptedMAC = new byte[SerializationConstants.TYPE_LEN_MAC];
        SignatureMessage previous = null;
        for (int i = 1; i <= 10000000; i *= 10) {
            byte[] fakeEncrypted = new byte[i];
            r.nextBytes(fakeEncrypted);
            r.nextBytes(fakeEncryptedMAC);
            SignatureMessage sm = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, 0, 0);
            assertNotNull(sm);
            assertFalse(sm.equals(null));
            SignatureMessage sm2 = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, 0, 0);
            assertNotNull(sm2);
            assertTrue(sm.equals(sm2));
            assertFalse(sm.equals(previous));
            previous = sm;
        }
        for (int i = -128; i < 128; i++) {
            byte[] fakeEncrypted = new byte[1000];
            Arrays.fill(fakeEncrypted, (byte) i);
            Arrays.fill(fakeEncryptedMAC, (byte) i);
            SignatureMessage current = new SignatureMessage(OTRv.THREE, fakeEncrypted, fakeEncryptedMAC, 0, 0);
            assertNotNull(current);
            assertFalse(current.equals(null));
            assertFalse(current.equals(previous));
            previous = current;
        }
    }
}
