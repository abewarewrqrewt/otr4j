package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Collections;

import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.messages.IdentityMessages.validate;

@SuppressWarnings("ConstantConditions")
public final class IdentityMessagesTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
    private final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
    private final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);

    @Test(expected = NullPointerException.class)
    public void testValidateNull() throws OtrCryptoException, ValidationException {
        validate(null);
    }

    @Test
    public void testValidateIdentity() throws OtrCryptoException, ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(),
            Collections.singleton(4), System.currentTimeMillis() / 1000 + 86400, null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile, null, longTermKeyPair);
        final IdentityMessage message = new IdentityMessage(4, SMALLEST_TAG, HIGHEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey());
        validate(message);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateIdentityNullClientProfile() throws OtrCryptoException, ValidationException {
        final IdentityMessage message = new IdentityMessage(4, HIGHEST_TAG, SMALLEST_TAG, null,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey());
        validate(message);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateIdentityNullEcdhPublicKey() throws OtrCryptoException, ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(),
            Collections.singleton(4), System.currentTimeMillis() / 1000 + 86400, null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile, null, longTermKeyPair);
        final IdentityMessage message = new IdentityMessage(4, HIGHEST_TAG, SMALLEST_TAG, profilePayload,
                null, dhKeyPair.getPublicKey());
        validate(message);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateIdentityNullDhPublicKey() throws OtrCryptoException, ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(),
            Collections.singleton(4), System.currentTimeMillis() / 1000 + 86400, null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile, null, longTermKeyPair);
        final IdentityMessage message = new IdentityMessage(4, HIGHEST_TAG, SMALLEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), null);
        validate(message);
    }

    @Test(expected = ValidationException.class)
    public void testValidateIdentityInconsistentInstanceTag() throws OtrCryptoException, ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(),
            Collections.singleton(4), System.currentTimeMillis() / 1000 + 86400, null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile, null, longTermKeyPair);
        final IdentityMessage message = new IdentityMessage(4, HIGHEST_TAG, SMALLEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey());
        validate(message);
    }
}
