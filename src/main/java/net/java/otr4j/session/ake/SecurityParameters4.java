package net.java.otr4j.session.ake;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;

import java.math.BigInteger;

import static java.util.Objects.requireNonNull;

/**
 * Container for OTRv4 security parameters.
 */
public final class SecurityParameters4 {

    private final Component initializationComponent;
    private final ECDHKeyPair ecdhKeyPair;
    private final DHKeyPair dhKeyPair;
    private final Point x;
    private final BigInteger a;

    /**
     * Security parameters for an OTRv4 encrypted message state.
     *
     * @param initializationComponent The initialization component, that is the side (ours or theirs) which will be
     *                                updated with the deterministically generated key pairs.
     * @param ecdhKeyPair             Our ECDH key pair.
     * @param dhKeyPair               Our DH key pair.
     * @param x                       Their ECDH public key.
     * @param a                       Their DH public key.
     */
    SecurityParameters4(@Nonnull final Component initializationComponent, @Nonnull final ECDHKeyPair ecdhKeyPair,
                        @Nonnull final DHKeyPair dhKeyPair, @Nonnull final Point x, @Nonnull final BigInteger a) {
        this.initializationComponent = requireNonNull(initializationComponent);
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
    }

    @Nonnull
    public Component getInitializationComponent() {
        return initializationComponent;
    }

    @Nonnull
    public ECDHKeyPair getEcdhKeyPair() {
        return ecdhKeyPair;
    }

    @Nonnull
    public DHKeyPair getDhKeyPair() {
        return dhKeyPair;
    }

    @Nonnull
    public Point getX() {
        return x;
    }

    @Nonnull
    public BigInteger getA() {
        return a;
    }

    /**
     * Initialization component, indicating whether our own keys will be preinitialized with pre-defined generated ECDH
     * and DH keys, or theirs.
     */
    public enum Component {
        OURS, THEIRS
    }
}
