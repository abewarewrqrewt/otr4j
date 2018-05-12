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
     * Initialization component, indicating whether our own keys will be pre-initialized with pre-defined generated ECDH
     * and DH keys, or theirs.
     * <p>
     * More information on this enum can be found in the OTRv4 spec. OURS/THEIRS refers to which side of the
     * double-ratchet will be initialized with especially crafted values such that the ratchet is initialized with
     * knowledge shared between the two parties. Refer to the "Interactive DAKE overview" and subsequent sections for
     * more information.
     * <p>
     * At the time of writing, the instructions were:
     * <pre>
     * Generates an ephemeral ECDH key pair, as defined in Generating ECDH and DH keys, but instead of using a random
     * value r, it will use : r = KDF_1(0x13 || K, 57). Securely replaces our_ecdh with the outputs.
     * Generates an ephemeral DH key pair, as defined in Generating ECDH and DH keys, but instead of using a random
     * value r, it will use : r = KDF_1(0x14 || K, 80). Securely replaces our_dh with the outputs.
     * </pre>
     */
    public enum Component {
        /**
         * OURS, indicating that we are representing <i>Bob</i>, as defined in the spec. This means that we will
         * generate crafted values for our (i.e. Bob's) side of the double ratchet.
         */
        OURS,
        /**
         * THEIRS, indicating that we are representing <i>Alice</i>, as defined in the spec. This means that we will
         * generate crafted values for Bob's side (i.e. not our side) of the double ratchet.
         */
        THEIRS
    }
}
