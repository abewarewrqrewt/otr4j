package net.java.otr4j.profile;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.ECDHKeyPair;

import java.security.SecureRandom;
import java.util.HashSet;

import static java.util.Collections.singleton;

public final class ClientProfileTestUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ECDHKeyPair longTermKeyPair;

    private final long expirationTime;

    /**
     * Construct user profile test utils with default parameters.
     */
    public ClientProfileTestUtils() {
        this.longTermKeyPair = ECDHKeyPair.generate(RANDOM);
        // By default set expiration time of 1 day in future.
        this.expirationTime = System.currentTimeMillis() / 1000 + 86400;
    }

    public ClientProfile createUserProfile() {
        // TODO produce user profile signature.
        return new ClientProfile(0, 0x100, this.longTermKeyPair.getPublicKey(),
            singleton(Session.OTRv.FOUR), this.expirationTime, new byte[0], new byte[114]);
    }

    public ClientProfile createTransitionalUserProfile() {
        final HashSet<Integer> versions = new HashSet<>();
        versions.add(Session.OTRv.THREE);
        versions.add(Session.OTRv.FOUR);
        // TODO produce transitional signature.
        final byte[] transitionalSignature = new byte[20];
        // TODO produce user profile signature.
        final byte[] profileSignature = new byte[114];
        return new ClientProfile(0, 0x100, this.longTermKeyPair.getPublicKey(), versions,
            this.expirationTime, transitionalSignature, profileSignature);
    }

}
