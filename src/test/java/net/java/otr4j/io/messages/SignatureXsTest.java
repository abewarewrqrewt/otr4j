package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.UnsupportedTypeException;
import org.junit.Test;

import java.net.ProtocolException;

import static net.java.otr4j.io.messages.SignatureXs.readSignatureX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public final class SignatureXsTest {

    @Test
    public void testReadMysteriousXOtrInputStreamReadBehavior() throws OtrCryptoException, UnsupportedTypeException, ProtocolException {
        // This test uses nonsensicle data and as such it does not verify
        // correct parsing of the read public key material. However, it does
        // test the reading behavior of OtrInputStream expected for such a read
        // operation.
        final byte[] data = new byte[] {
            0, 0, // public key -> type
            0, 0, 0, 1, // public key -> p -> size
            1, // public key -> p
            0, 0, 0, 1, // public key -> q -> size
            16, // public key -> q (needs certain size such that signature of public key has length > 0)
            0, 0, 0, 1, // public key -> g -> size
            3, // public key -> g
            0, 0, 0, 1, // public key -> y -> size
            4, // public key -> y
            0, 0, 0, 5, // dhKeyID
            8, // read signature of public key
        };
        final SignatureX sigX = readSignatureX(data);
        assertNotNull(sigX);
        assertNotNull(sigX.getLongTermPublicKey());
        assertEquals(5, sigX.getDhKeyID());
        // FIXME I don't want to forget about this just yet, but currently we cannot access the signature directly. (Do I care the remove the last check?)
//        assertArrayEquals(new byte[] { 8 }, sigX.signature);
    }
}
