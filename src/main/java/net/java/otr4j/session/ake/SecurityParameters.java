/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.crypto.DHKeyPairJ;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;

/**
 * Container that stores all the security parameters that were negotiated during
 * AKE. These parameters are passed on to initiate the encrypted message state.
 *
 * @author Danny van Heumen
 */
public final class SecurityParameters {

    private final int version;
    private final DHKeyPairJ localDHKeyPair;
    private final DSAPublicKey remoteLongTermPublicKey;
    private final DHPublicKey remoteDHPublicKey;
    private final SharedSecret s;

    SecurityParameters(final int version, @Nonnull final DHKeyPairJ localDHKeyPair,
            @Nonnull final DSAPublicKey remoteLongTermPublicKey, @Nonnull final DHPublicKey remoteDHPublicKey,
            @Nonnull final SharedSecret s) {
        if (version < 2 || version > 3) {
            throw new IllegalArgumentException("Illegal version value specified.");
        }
        this.version = version;
        this.localDHKeyPair = requireNonNull(localDHKeyPair);
        this.remoteLongTermPublicKey = requireNonNull(remoteLongTermPublicKey);
        try {
            this.remoteDHPublicKey = OtrCryptoEngine.verify(remoteDHPublicKey);
        } catch (final OtrCryptoException ex) {
            throw new IllegalArgumentException("Illegal D-H Public Key provided.", ex);
        }
        this.s = requireNonNull(s);
    }

    /**
     * Get the protocol version.
     *
     * @return Returns protocol version.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Get the local DH keypair.
     *
     * @return Returns the DH key pair.
     */
    @Nonnull
    public DHKeyPairJ getLocalDHKeyPair() {
        return localDHKeyPair;
    }

    /**
     * Get the remote long-term DSA public key.
     *
     * @return Returns the DSA public key.
     */
    @Nonnull
    public DSAPublicKey getRemoteLongTermPublicKey() {
        return remoteLongTermPublicKey;
    }

    /**
     * Get the remote DH public key.
     *
     * @return Returns the DH public key.
     */
    @Nonnull
    public DHPublicKey getRemoteDHPublicKey() {
        return remoteDHPublicKey;
    }

    /**
     * Get the shared secret 's'.
     *
     * @return The shared secret 's'.
     */
    @Nonnull
    public SharedSecret getS() {
        return s;
    }
}
