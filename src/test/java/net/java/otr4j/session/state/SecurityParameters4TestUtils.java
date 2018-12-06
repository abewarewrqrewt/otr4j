package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

public final class SecurityParameters4TestUtils {

    public static SecurityParameters4 createSecurityParameters4(@Nonnull final SecurityParameters4.Component component,
            @Nonnull final ECDHKeyPair ecdhKeyPair, @Nonnull final DHKeyPair dhKeyPair,
            @Nonnull final Point theirDHPublicKey, @Nonnull final BigInteger theirECDHPublicKey,
            @Nonnull final ClientProfile ourProfile, @Nonnull final ClientProfile theirProfile) {
        return new SecurityParameters4(component, ecdhKeyPair, dhKeyPair, theirDHPublicKey, theirECDHPublicKey, ourProfile, theirProfile);
    }
}
