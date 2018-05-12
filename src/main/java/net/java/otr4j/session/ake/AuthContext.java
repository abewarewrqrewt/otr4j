/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import java.security.KeyPair;
import java.security.SecureRandom;

import javax.annotation.Nonnull;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.profile.UserProfile;

/**
 * Context required for authentication state implementations.
 *
 * @author Danny van Heumen
 */
public interface AuthContext {

    /**
     * Update AKE state in context.
     *
     * @param state The new AKE state.
     */
    void setState(@Nonnull AuthState state);

    /**
     * Transition to message state ENCRYPTED based on the provided parameters. (OTRv2/OTRv3)
     *
     * @param params Instance containing all parameters that are negotiated
     * during the AKE that are relevant to setting up and maintaining the
     * encrypted message state.
     * @throws InteractionFailedException Thrown in case transition into
     * ENCRYPTED message state fails.
     */
    void secure(@Nonnull SecurityParameters params) throws InteractionFailedException;

    /**
     * Transition to message state ENCRYPTED based on the provided parameters. (OTRv4)
     *
     * @param params The security parameters as negotiated in the key exchange.
     */
    void secure(@Nonnull SecurityParameters4 params) throws OtrCryptoException;

    /**
     * Access to SecureRandom instance.
     *
     * @return Returns SecureRandom instance.
     */
    @Nonnull
    SecureRandom secureRandom();

    /**
     * Access to long-term key pair.
     *
     * @return Returns long-term key pair.
     */
    // FIXME do we need this method or was this a mistake, as this information can be retrieved through UserProfile?
    @Nonnull
    KeyPair getLocalKeyPair();

    /**
     * Sender instance tag value.
     *
     * @return Returns sender instance tag value.
     */
    @Nonnull
    InstanceTag getSenderInstanceTag();

    /**
     * Receiver instance tag value.
     *
     * @return Returns recipient instance tag value.
     */
    @Nonnull
    InstanceTag getReceiverInstanceTag();

    /**
     * User profile for the client.
     *
     * @return Returns the user profile for this client.
     */
    @Nonnull
    UserProfile getUserProfile();

    /**
     * InteractionFailedException indicates an error happened while interacting
     * with AKE's context.
     *
     * This exception is defined for users of the ake package, i.e. AuthContext
     * implementors, such that they can throw an exception in case of failure.
     * InteractionFailedException is the only recognized checked exception which
     * the ake package takes into account inside the implementation logic.
     */
    final class InteractionFailedException extends Exception {

        private static final long serialVersionUID = -8731442427746963923L;

        public InteractionFailedException(@Nonnull final Throwable cause) {
            super(cause);
        }
    }
}
