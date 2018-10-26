package net.java.otr4j.api;

import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.messages.ClientProfilePayload;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.TreeSet;

import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;

public final class ClientProfileTestUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair eddsaLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);

    private final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();

    private final KeyPair dsaKeyPair = OtrCryptoEngine.generateDSAKeyPair();

    private final long expirationTime = System.currentTimeMillis() / 1000 + 86400;

    /**
     * Construct user profile test utils with default parameters.
     */
    public ClientProfileTestUtils() {
    }

    public ClientProfilePayload createUserProfile() {
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, this.eddsaLongTermKeyPair.getPublicKey(),
                this.forgingKey, singleton(Session.OTRv.FOUR), this.expirationTime, null);
        return ClientProfilePayload.sign(profile, null, this.eddsaLongTermKeyPair);
    }

    public ClientProfilePayload createTransitionalUserProfile() {
        final TreeSet<Integer> versions = new TreeSet<>();
        versions.add(Session.OTRv.THREE);
        versions.add(Session.OTRv.FOUR);
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, this.eddsaLongTermKeyPair.getPublicKey(),
                this.forgingKey, versions, this.expirationTime, (DSAPublicKey) this.dsaKeyPair.getPublic());
        return ClientProfilePayload.sign(profile, (DSAPrivateKey) this.dsaKeyPair.getPrivate(), this.eddsaLongTermKeyPair);
    }
}
