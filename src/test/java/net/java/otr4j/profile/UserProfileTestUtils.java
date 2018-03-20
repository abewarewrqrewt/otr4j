package net.java.otr4j.profile;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.ECDHKeyPair;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;

public final class UserProfileTestUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ECDHKeyPair longTermKeyPair;

    private final ECDHKeyPair sharedPrekeyKeyPair;

    private final long expirationTime;

    /**
     * Construct user profile test utils with default parameters.
     */
    public UserProfileTestUtils() {
        this.longTermKeyPair = ECDHKeyPair.generate(RANDOM);
        this.sharedPrekeyKeyPair = ECDHKeyPair.generate(RANDOM);
        // By default set expiration time of 1 day in future.
        this.expirationTime = System.currentTimeMillis() / 1000 + 86400;
    }

    public UserProfile createUserProfile() {
        // TODO produce user profile signature.
        final byte[] profileSignature = new byte[0];
        return new UserProfile(this.longTermKeyPair.getPublicKey(), Collections.singleton(Session.OTRv.FOUR),
            this.expirationTime, this.sharedPrekeyKeyPair.getPublicKey(), profileSignature, null);
    }

    public UserProfile createTransitionalUserProfile() {
        final HashSet<Integer> versions = new HashSet<>();
        versions.add(Session.OTRv.THREE);
        versions.add(Session.OTRv.FOUR);
        // TODO produce transitional signature.
        final byte[] transitionalSignature = new byte[0];
        // TODO produce user profile signature.
        final byte[] profileSignature = new byte[0];
        return new UserProfile(this.longTermKeyPair.getPublicKey(), versions, this.expirationTime,
            this.sharedPrekeyKeyPair.getPublicKey(), transitionalSignature, profileSignature);
    }

}
