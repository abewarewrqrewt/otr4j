/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;

/**
 * Container for OTRv4 security parameters.
 * <p>
 * Container that contains the negotiated security parameters during an OTRv4 Interactive DAKE session.
 */
final class SecurityParameters4 implements AutoCloseable {

    private final Component initializationComponent;
    private final ECDHKeyPair ecdhKeyPair;
    private final DHKeyPair dhKeyPair;
    private final Point theirECDHPublicKey;
    private final BigInteger theirDHPublicKey;
    private final ClientProfile ourProfile;
    private final ClientProfile theirProfile;

    /**
     * Security parameters for an OTRv4 encrypted message state.
     *
     * @param initializationComponent The initialization component, that is the side (ours or theirs) which will be
     *                                updated with the deterministically generated key pairs.
     * @param ecdhKeyPair             Our ECDH key pair.
     * @param dhKeyPair               Our DH key pair.
     * @param theirECDHPublicKey      Their ECDH public key. Typically called 'X' for Alice, or 'Y' for Bob.
     * @param theirDHPublicKey        Their DH public key. Typically called 'a' for Alice, or 'b' for Bob.
     */
    SecurityParameters4(@Nonnull final Component initializationComponent, @Nonnull final ECDHKeyPair ecdhKeyPair,
            @Nonnull final DHKeyPair dhKeyPair, @Nonnull final Point theirECDHPublicKey,
            @Nonnull final BigInteger theirDHPublicKey, @Nonnull final ClientProfile ourProfile,
            @Nonnull final ClientProfile theirProfile) {
        this.initializationComponent = requireNonNull(initializationComponent);
        this.ecdhKeyPair = requireNonNull(ecdhKeyPair);
        this.dhKeyPair = requireNonNull(dhKeyPair);
        this.theirECDHPublicKey = requireNonNull(theirECDHPublicKey);
        this.theirDHPublicKey = requireNonNull(theirDHPublicKey);
        this.ourProfile = requireNonNull(ourProfile);
        this.theirProfile = requireNonNull(theirProfile);
    }

    @Override
    public void close() {
        this.ecdhKeyPair.close();
        this.dhKeyPair.close();
    }

    /**
     * Get the component that should be initialized in the Double Ratchet.
     *
     * @return Returns initialization component.
     */
    @Nonnull
    Component getInitializationComponent() {
        return initializationComponent;
    }

    /**
     * Get the Ephemeral ECDH public key. Typically 'X' for Alice, or 'Y' for Bob.
     *
     * @return Returns ECDH public key.
     */
    @Nonnull
    Point getTheirECDHPublicKey() {
        return theirECDHPublicKey;
    }

    /**
     * Get the Ephemeral DH public key. Typically 'A' for Alice, or 'B' for Bob.
     *
     * @return Returns DH public key.
     */
    @Nonnull
    BigInteger getTheirDHPublicKey() {
        return theirDHPublicKey;
    }

    /**
     * Get our client profile used during DAKE.
     *
     * @return Returns our client profile.
     */
    @Nonnull
    ClientProfile getOurProfile() {
        return ourProfile;
    }

    /**
     * Get the other party's client profile.
     *
     * @return Returns their client profile.
     */
    @Nonnull
    ClientProfile getTheirProfile() {
        return theirProfile;
    }

    /**
     * Generate a OTRv4 shared secret based on the keys contained in the SecurityParameters4 instance.
     *
     * @param random secure random instance
     * @return Returns a newly generated SharedSecret4 instance based on contained keys.
     */
    @Nonnull
    SharedSecret4 generateSharedSecret(@Nonnull final SecureRandom random) {
        return new SharedSecret4(random, this.dhKeyPair, this.ecdhKeyPair, this.theirDHPublicKey, this.theirECDHPublicKey);
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
    enum Component {
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
