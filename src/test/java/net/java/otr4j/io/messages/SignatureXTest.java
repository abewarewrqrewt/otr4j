package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoException;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.crypto.OtrCryptoEngine.generateDSAKeyPair;
import static net.java.otr4j.util.SecureRandoms.randomBytes;

@SuppressWarnings("ConstantConditions")
public final class SignatureXTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DSAPublicKey publicKey = (DSAPublicKey) generateDSAKeyPair().getPublic();

    @Test(expected = NullPointerException.class)
    public void testConstructNullDSAPublicKey() {
        new SignatureX(null, 0, new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullSignature() {
        new SignatureX(publicKey, 0, null);
    }

    @Test
    public void testConstruct() {
        final byte[] signature = randomBytes(RANDOM, new byte[56]);
        new SignatureX(publicKey, 0, signature);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifySignatureNullSignature() throws OtrCryptoException {
        final byte[] signature = randomBytes(RANDOM, new byte[56]);
        final SignatureX sig = new SignatureX(publicKey, 0, signature);
        sig.verify(null);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifySignature() throws OtrCryptoException {
        final int signatureLength = publicKey.getParams().getQ().bitLength() / 8 * 2;
        final byte[] signature = randomBytes(RANDOM, new byte[signatureLength]);
        final SignatureX sig = new SignatureX(publicKey, 0, signature);
        sig.verify(randomBytes(RANDOM, new byte[signatureLength]));
    }
}
