package net.java.otr4j.profile;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.messages.ClientProfilePayload;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.TreeSet;

import static java.util.Collections.singleton;

public final class ClientProfileTestUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair eddsaLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);

    private final KeyPair dsaKeyPair = OtrCryptoEngine.generateDSAKeyPair();

    private final long expirationTime = System.currentTimeMillis() / 1000 + 86400;

    /**
     * Construct user profile test utils with default parameters.
     */
    public ClientProfileTestUtils() {
    }

    public ClientProfilePayload createUserProfile() {
        final ClientProfile profile = new ClientProfile(0x100, this.eddsaLongTermKeyPair.getPublicKey(),
            singleton(Session.OTRv.FOUR), this.expirationTime, null);
        return ClientProfilePayload.sign(profile, null, this.eddsaLongTermKeyPair);
    }

    public ClientProfilePayload createTransitionalUserProfile() {
        final TreeSet<Integer> versions = new TreeSet<>();
        versions.add(Session.OTRv.THREE);
        versions.add(Session.OTRv.FOUR);
        final ClientProfile profile = new ClientProfile(0x100, this.eddsaLongTermKeyPair.getPublicKey(),
            versions, this.expirationTime, (DSAPublicKey) this.dsaKeyPair.getPublic());
        return ClientProfilePayload.sign(profile, (DSAPrivateKey) this.dsaKeyPair.getPrivate(), this.eddsaLongTermKeyPair);
    }
}
