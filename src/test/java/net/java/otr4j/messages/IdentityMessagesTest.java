/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;

import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.messages.IdentityMessages.validate;

@SuppressWarnings("ConstantConditions")
public final class IdentityMessagesTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
    private final Point forgingPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
    private final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
    private final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);

    @Test(expected = NullPointerException.class)
    public void testValidateNullMessage() throws ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), this.forgingPublicKey,
                Collections.singleton(4), null);
        validate(null, profile);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateNullProfile() throws ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), this.forgingPublicKey,
                Collections.singleton(4), null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile,
                System.currentTimeMillis() / 1000 + 86400, null, longTermKeyPair);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final IdentityMessage message = new IdentityMessage(4, SMALLEST_TAG, HIGHEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey(), ourFirstECDHPublicKey, ourFirstDHPublicKey);
        validate(message, null);
    }

    @Test
    public void testValidateIdentity() throws ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), this.forgingPublicKey,
                Collections.singleton(4), null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile,
                System.currentTimeMillis() / 1000 + 86400, null, longTermKeyPair);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final IdentityMessage message = new IdentityMessage(4, SMALLEST_TAG, HIGHEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey(), ourFirstECDHPublicKey, ourFirstDHPublicKey);
        validate(message, profile);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateIdentityNullClientProfile() throws ValidationException {
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final IdentityMessage message = new IdentityMessage(4, HIGHEST_TAG, SMALLEST_TAG, null,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey(), ourFirstECDHPublicKey, ourFirstDHPublicKey);
        validate(message, null);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateIdentityNullEcdhPublicKey() throws ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), this.forgingPublicKey,
                Collections.singleton(4), null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile,
                System.currentTimeMillis() / 1000 + 86400, null, longTermKeyPair);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final IdentityMessage message = new IdentityMessage(4, HIGHEST_TAG, SMALLEST_TAG, profilePayload,
                null, dhKeyPair.getPublicKey(), ourFirstECDHPublicKey, ourFirstDHPublicKey);
        validate(message, profile);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateIdentityNullDhPublicKey() throws ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), this.forgingPublicKey,
                Collections.singleton(4), null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile,
                System.currentTimeMillis() / 1000 + 86400, null, longTermKeyPair);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final IdentityMessage message = new IdentityMessage(FOUR, HIGHEST_TAG, SMALLEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), null, ourFirstECDHPublicKey, ourFirstDHPublicKey);
        validate(message, profile);
    }

    @Test(expected = ValidationException.class)
    public void testValidateIdentityInconsistentInstanceTag() throws ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), this.forgingPublicKey,
                Collections.singleton(4), null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile,
                System.currentTimeMillis() / 1000 + 86400, null, longTermKeyPair);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final IdentityMessage message = new IdentityMessage(FOUR, HIGHEST_TAG, SMALLEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey(), ourFirstECDHPublicKey, ourFirstDHPublicKey);
        validate(message, profile);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateIdentityNullFirstECDHPublicKey() throws ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), this.forgingPublicKey,
                Collections.singleton(4), null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile,
                System.currentTimeMillis() / 1000 + 86400, null, longTermKeyPair);
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final IdentityMessage message = new IdentityMessage(FOUR, HIGHEST_TAG, SMALLEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey(), null, ourFirstDHPublicKey);
        validate(message, profile);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateIdentityNullFirstDHPublicKey() throws ValidationException {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), this.forgingPublicKey,
                Collections.singleton(4), null);
        final ClientProfilePayload profilePayload = ClientProfilePayload.sign(profile,
                System.currentTimeMillis() / 1000 + 86400, null, longTermKeyPair);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final IdentityMessage message = new IdentityMessage(FOUR, HIGHEST_TAG, SMALLEST_TAG, profilePayload,
                ecdhKeyPair.getPublicKey(), dhKeyPair.getPublicKey(), ourFirstECDHPublicKey, null);
        validate(message, profile);
    }
}
