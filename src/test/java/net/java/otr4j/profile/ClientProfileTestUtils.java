package net.java.otr4j.profile;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.io.messages.ClientProfilePayload;

import java.security.SecureRandom;
import java.util.HashSet;

import static java.util.Collections.singleton;

public final class ClientProfileTestUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final EdDSAKeyPair eddsaLongTermKeyPair;

    private final long expirationTime;

    /**
     * Construct user profile test utils with default parameters.
     */
    public ClientProfileTestUtils() {
        this.eddsaLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        // By default set expiration time of 1 day in future.
        this.expirationTime = System.currentTimeMillis() / 1000 + 86400;
    }

    public ClientProfilePayload createUserProfile() {
        // TODO produce user profile signature.
        final ClientProfile profile = new ClientProfile(0x100, this.eddsaLongTermKeyPair.getPublicKey(),
            singleton(Session.OTRv.FOUR), this.expirationTime);
        // FIXME non-functional conversion. Needs to be fixed.
        return ClientProfilePayload.sign(profile, null, this.eddsaLongTermKeyPair);
    }

    public ClientProfilePayload createTransitionalUserProfile() {
        final HashSet<Integer> versions = new HashSet<>();
        versions.add(Session.OTRv.THREE);
        versions.add(Session.OTRv.FOUR);
        final ClientProfile profile = new ClientProfile(0x100, this.eddsaLongTermKeyPair.getPublicKey(),
            versions, this.expirationTime);
        // FIXME non-functional conversion. Needs to be fixed.
        return ClientProfilePayload.sign(profile, null, this.eddsaLongTermKeyPair);
    }
}
