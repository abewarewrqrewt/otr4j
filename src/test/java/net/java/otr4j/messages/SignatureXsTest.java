/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.UnsupportedTypeException;
import org.junit.Test;

import java.net.ProtocolException;
import java.security.SecureRandom;

import static net.java.otr4j.messages.SignatureXs.readSignatureX;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertEquals;

public final class SignatureXsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = ProtocolException.class)
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
        readSignatureX(data);
    }

    @Test
    public void testReadSignatureX() throws ProtocolException, OtrCryptoException, UnsupportedTypeException {
        final DSAKeyPair keypair = DSAKeyPair.generateDSAKeyPair();
        final byte[] signature = keypair.sign(randomBytes(RANDOM, new byte[10]));
        final SignatureX sigX = new SignatureX(keypair.getPublic(), 1, signature);
        final byte[] input = new OtrOutputStream().write(sigX).toByteArray();
        final SignatureX readSigX = readSignatureX(input);
        assertEquals(sigX, readSigX);
    }
}
