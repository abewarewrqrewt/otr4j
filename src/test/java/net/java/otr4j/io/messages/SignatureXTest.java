package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import org.junit.Test;

import java.security.interfaces.DSAPublicKey;

@SuppressWarnings("ConstantConditions")
public final class SignatureXTest {

    private static final DSAPublicKey publicKey = (DSAPublicKey) OtrCryptoEngine.generateDSAKeyPair().getPublic();

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
        new SignatureX(publicKey, 0, new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifySignatureNullSignature() throws OtrCryptoException {
        final SignatureX sig = new SignatureX(publicKey, 0, new byte[56]);
        sig.verify(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testVerifySignatureZeroLengthSignature() throws OtrCryptoException {
        final int signatureLength = publicKey.getParams().getQ().bitLength() / 8 * 2;
        final SignatureX sig = new SignatureX(publicKey, 0, new byte[signatureLength]);
        sig.verify(new byte[0]);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifySignature() throws OtrCryptoException {
        final int signatureLength = publicKey.getParams().getQ().bitLength() / 8 * 2;
        final SignatureX sig = new SignatureX(publicKey, 0, new byte[signatureLength]);
        sig.verify(new byte[signatureLength]);
    }
}
