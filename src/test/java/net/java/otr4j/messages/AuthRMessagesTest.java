package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.HIGHEST_VALUE;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_VALUE;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.crypto.ed448.Point.createPoint;
import static net.java.otr4j.messages.AuthRMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;

public final class AuthRMessagesTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testValidateSuccessful() throws OtrCryptoException, ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                forgingKey, singleton(OTRv.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = ClientProfilePayload.sign(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final ECDHKeyPair theirX = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair theirA = DHKeyPair.generate(RANDOM);
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final ECDHKeyPair ourY = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair ourB = DHKeyPair.generate(RANDOM);
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singleton(OTRv.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = ClientProfilePayload.sign(ourProfile, Long.MAX_VALUE/1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX.getPublicKey(), ourY.getPublicKey(),
                theirA.getPublicKey(), ourB.getPublicKey(), SMALLEST_VALUE, HIGHEST_VALUE, "?OTRv4?",
                "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY.getPublicKey(), m);
        final AuthRMessage message = new AuthRMessage(OTRv.FOUR, SMALLEST_TAG, HIGHEST_TAG, theirPayload,
                theirX.getPublicKey(), theirA.getPublicKey(), sigma);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY.getPublicKey(), ourB.getPublicKey(), "?OTRv4?");
    }

    @Test(expected = ValidationException.class)
    public void testValidateInstanceTagMismatch() throws OtrCryptoException, ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(new InstanceTag(257), theirLongTermKeyPair.getPublicKey(),
                forgingKey, singleton(OTRv.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = ClientProfilePayload.sign(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirX = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirA = DHKeyPair.generate(RANDOM).getPublicKey();
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourY = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singleton(OTRv.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = ClientProfilePayload.sign(ourProfile, Long.MAX_VALUE/1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB,
                SMALLEST_VALUE, HIGHEST_VALUE, "?OTRv4?", "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY, m);
        final AuthRMessage message = new AuthRMessage(OTRv.FOUR, SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX,
                theirA, sigma);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY, ourB, "?OTRv4?");
    }

    @Test(expected = ValidationException.class)
    public void testValidateIllegalECDHPublicKey() throws OtrCryptoException, ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                forgingKey, singleton(OTRv.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = ClientProfilePayload.sign(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirX = createPoint(ONE, ONE);
        final BigInteger theirA = DHKeyPair.generate(RANDOM).getPublicKey();
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourY = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singleton(OTRv.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = ClientProfilePayload.sign(ourProfile, Long.MAX_VALUE/1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB,
                SMALLEST_VALUE, HIGHEST_VALUE, "?OTRv4?", "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY, m);
        final AuthRMessage message = new AuthRMessage(OTRv.FOUR, SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX,
                theirA, sigma);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY, ourB, "?OTRv4?");
    }

    @Test(expected = OtrCryptoException.class)
    public void testValidateIllegalDHPublicKey() throws OtrCryptoException, ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                forgingKey, singleton(OTRv.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = ClientProfilePayload.sign(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirX = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirA = ZERO;
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourY = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singleton(OTRv.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = ClientProfilePayload.sign(ourProfile, Long.MAX_VALUE/1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB,
                SMALLEST_VALUE, HIGHEST_VALUE, "?OTRv4?", "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY, m);
        final AuthRMessage message = new AuthRMessage(OTRv.FOUR, SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX,
                theirA, sigma);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY, ourB, "?OTRv4?");
    }

    @Test(expected = OtrCryptoException.class)
    public void testValidateBadMessage() throws OtrCryptoException, ValidationException {
        // Define their client
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                forgingKey, singleton(OTRv.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirPayload = ClientProfilePayload.sign(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirX = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirA = ZERO;
        // Define our client
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourY = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair();
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singleton(OTRv.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourPayload = ClientProfilePayload.sign(ourProfile, Long.MAX_VALUE/1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        // Define the message to be validated
        final byte[] m = MysteriousT4.encode(AUTH_R, theirPayload, ourPayload, theirX, ourY, theirA, ourB,
                SMALLEST_VALUE, HIGHEST_VALUE, "?OTRv4?", "", "");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, ourForgingKey, theirLongTermKeyPair.getPublicKey(),
                ourY, m);
        final AuthRMessage message = new AuthRMessage(OTRv.FOUR, SMALLEST_TAG, HIGHEST_TAG, theirPayload, theirX,
                theirA, sigma);
        validate(message, ourPayload, ourProfile, theirProfile, "alice@network", "bob@network",
                ourY, ourB, "?OTRv4?");
    }
}