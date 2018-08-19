package net.java.otr4j.session.ake;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ECDHKeyPair;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;

/**
 * Container for OTRv4 security parameters.
 * <p>
 * Container that contains the negotiated security parameters during an OTRv4 Interactive DAKE session.
 */
// FIXME migrate into Message State state machine.
public final class SecurityParameters4 {

    private final Component initializationComponent;
    private final ECDHKeyPair ecdhKeyPair;
    private final DHKeyPair dhKeyPair;
    private final Point x;
    private final BigInteger a;
    private final ClientProfile ourProfile;
    private final ClientProfile theirProfile;

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
    // TODO consider renaming x and a to something less wrong. x and a are specific for alice, however SecurityParameters4 is used for both parties.
    SecurityParameters4(@Nonnull final Component initializationComponent, @Nonnull final ECDHKeyPair ecdhKeyPair,
            @Nonnull final DHKeyPair dhKeyPair, @Nonnull final Point x, @Nonnull final BigInteger a,
            @Nonnull final ClientProfile ourProfile, @Nonnull final ClientProfile theirProfile) {
        this.initializationComponent = requireNonNull(initializationComponent);
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
        this.ourProfile = requireNonNull(ourProfile);
        this.theirProfile = requireNonNull(theirProfile);
    }

    /**
     * Get the component that should be initialized in the Double Ratchet.
     *
     * @return Returns initialization component.
     */
    @Nonnull
    public Component getInitializationComponent() {
        return initializationComponent;
    }

    /**
     * Get local ephemeral ECDH key pair.
     *
     * @return Returns ECDH key pair.
     */
    @Nonnull
    public ECDHKeyPair getEcdhKeyPair() {
        return ecdhKeyPair;
    }

    /**
     * Get local ephemeral DH key pair.
     *
     * @return Returns DH key pair.
     */
    @Nonnull
    public DHKeyPair getDhKeyPair() {
        return dhKeyPair;
    }

    /**
     * Get the Ephemeral ECDH public key.
     *
     * @return Returns ECDH public key.
     */
    @Nonnull
    public Point getX() {
        return x;
    }

    /**
     * Get the Ephemeral DH public key.
     *
     * @return Returns DH public key.
     */
    @Nonnull
    public BigInteger getA() {
        return a;
    }

    /**
     * Get our client profile used during DAKE.
     *
     * @return Returns our client profile.
     */
    @Nonnull
    public ClientProfile getOurProfile() {
        return ourProfile;
    }

    /**
     * Get the other party's client profile.
     *
     * @return Returns their client profile.
     */
    @Nonnull
    public ClientProfile getTheirProfile() {
        return theirProfile;
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
