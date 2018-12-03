/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.messages.ClientProfilePayload;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

/**
 * Context required for authentication state implementations.
 *
 * @author Danny van Heumen
 */
public interface AuthContext {

    @Nonnull
    SecureRandom secureRandom();

    @Nonnull
    InstanceTag getSenderTag();

    @Nonnull
    InstanceTag getReceiverTag();

    @Nonnull
    ClientProfilePayload getClientProfilePayload();

    @Nonnull
    DSAKeyPair getLocalKeyPair();

    @Nonnull
    EdDSAKeyPair getLongTermKeyPair();

    @Nonnull
    String getLocalAccountID();

    @Nonnull
    String getRemoteAccountID();

    @Nonnull
    AuthState getAuthState();

    /**
     * Update AKE state in context.
     *
     * @param state The new AKE state.
     */
    void setAuthState(@Nonnull AuthState state);

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
    void secure(@Nonnull SecurityParameters4 params);

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

        /**
         * Constructor for InteractionFailedException.
         *
         * @param cause the root cause
         */
        public InteractionFailedException(@Nonnull final Throwable cause) {
            super(cause);
        }
    }
}
