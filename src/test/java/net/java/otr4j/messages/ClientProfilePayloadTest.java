package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import static java.util.Collections.singleton;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class ClientProfilePayloadTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final InstanceTag tag = InstanceTag.SMALLEST_TAG;

    private final EdDSAKeyPair keypair = EdDSAKeyPair.generate(RANDOM);

    private final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();

    private final KeyPair dsaKeyPair = OtrCryptoEngine.generateDSAKeyPair();

    @Test
    public void testConstructedPayloadIsReversible() throws ValidationException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, null);
        assertEquals(profile, ClientProfilePayload.sign(profile, null, keypair).validate());
    }

    @Test
    public void testConstructedPayloadWithDSAIsReversible() throws ValidationException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, (DSAPublicKey) this.dsaKeyPair.getPublic());
        assertEquals(profile, ClientProfilePayload.sign(profile, (DSAPrivateKey) dsaKeyPair.getPrivate(),
                keypair).validate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructedPayloadWithDSAWithoutDSASignature() throws ValidationException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, (DSAPublicKey) this.dsaKeyPair.getPublic());
        assertEquals(profile, ClientProfilePayload.sign(profile, null, keypair).validate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructedPayloadWithoutDSAPublicKeyWithDSASignature() throws ValidationException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, null);
        assertEquals(profile, ClientProfilePayload.sign(profile, (DSAPrivateKey) this.dsaKeyPair.getPrivate(), keypair)
                .validate());
    }

    @Test(expected = NullPointerException.class)
    public void testSignNullProfile() {
        ClientProfilePayload.sign(null, null, this.keypair);
    }

    @Test(expected = NullPointerException.class)
    public void testSignNullKeypair() {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, null);
        ClientProfilePayload.sign(profile, null, null);
    }
}