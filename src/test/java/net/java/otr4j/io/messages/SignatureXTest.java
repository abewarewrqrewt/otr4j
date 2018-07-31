package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoEngine;
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
}
