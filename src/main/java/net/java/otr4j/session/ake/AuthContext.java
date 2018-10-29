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
    void secure(@Nonnull SecurityParameters4 params);

    /**
     * Access to SecureRandom instance.
     *
     * @return Returns SecureRandom instance.
     */
    @Nonnull
    SecureRandom secureRandom();

    /**
     * Get the account ID of the local user.
     * <p>
     * Note that this account ID has to meet the requirements specified in OTRv4 spec.
     *
     * @return Returns the account ID of the local user.
     */
    @Nonnull
    String getLocalAccountID();

    /**
     * Get the account ID of the remote user.
     * <p>
     * Note that this account ID has to meet the requirements specified in OTRv4 spec.
     *
     * @return Returns the account ID of the remote user.
     */
    @Nonnull
    String getRemoteAccountID();

    /**
     * Access to long-term key pair. (OTRv2/OTRv3)
     *
     * @return Returns the long-term key pair.
     */
    @Nonnull
    DSAKeyPair getLocalKeyPair();

    /**
     * Access to the long-term Ed448-Goldilocks key pair. (OTRv4)
     *
     * @return Returns the long-term key pair.
     */
    // TODO think up a decent name for this, as not to confuse with the original OTRv2/OTRv3 local long-term key pair.
    @Nonnull
    EdDSAKeyPair getLongTermKeyPair();

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
     * Client profile payload, i.e. signed encode-ready instance of client profile.
     *
     * @return Returns the client profile for this client.
     */
    @Nonnull
    ClientProfilePayload getClientProfilePayload();

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
