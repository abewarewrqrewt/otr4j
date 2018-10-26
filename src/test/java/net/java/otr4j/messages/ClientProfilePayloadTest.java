package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import java.net.ProtocolException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import static java.util.Collections.singleton;
import static net.java.otr4j.messages.ClientProfilePayload.sign;
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
        assertEquals(profile, sign(profile, null, keypair).validate());
    }

    @Test
    public void testConstructedPayloadWithDSAIsReversible() throws ValidationException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, (DSAPublicKey) this.dsaKeyPair.getPublic());
        assertEquals(profile, sign(profile, (DSAPrivateKey) dsaKeyPair.getPrivate(),
                keypair).validate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructedPayloadWithDSAWithoutDSASignature() throws ValidationException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, (DSAPublicKey) this.dsaKeyPair.getPublic());
        assertEquals(profile, sign(profile, null, keypair).validate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructedPayloadWithoutDSAPublicKeyWithDSASignature() throws ValidationException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, null);
        assertEquals(profile, sign(profile, (DSAPrivateKey) this.dsaKeyPair.getPrivate(), keypair)
                .validate());
    }

    @Test(expected = NullPointerException.class)
    public void testSignNullProfile() {
        sign(null, null, this.keypair);
    }

    @Test(expected = NullPointerException.class)
    public void testSignNullKeypair() {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, null);
        sign(profile, null, null);
    }

    @Test
    public void testReadingWrittenClientProfilePayload() throws OtrCryptoException, ProtocolException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, null);
        final ClientProfilePayload payload = sign(profile, null, keypair);
        final OtrOutputStream out = new OtrOutputStream();
        payload.writeTo(out);
        final ClientProfilePayload parsedPayload = ClientProfilePayload.readFrom(new OtrInputStream(out.toByteArray()));
        assertEquals(payload, parsedPayload);
    }

    @Test
    public void testReadingWrittenClientProfilePayloadWithDSA() throws OtrCryptoException, ProtocolException {
        final ClientProfile profile = new ClientProfile(tag, keypair.getPublicKey(), forgingKey, singleton(OTRv.FOUR),
                System.currentTimeMillis() / 1000 + 86400, (DSAPublicKey) this.dsaKeyPair.getPublic());
        final ClientProfilePayload payload = sign(profile, (DSAPrivateKey) this.dsaKeyPair.getPrivate(), keypair);
        final OtrOutputStream out = new OtrOutputStream();
        payload.writeTo(out);
        final ClientProfilePayload parsedPayload = ClientProfilePayload.readFrom(new OtrInputStream(out.toByteArray()));
        assertEquals(payload, parsedPayload);
    }
}