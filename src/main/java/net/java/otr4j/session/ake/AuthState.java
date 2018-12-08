/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.messages.AbstractEncodedMessage;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;

/**
 * Interface for the AKE states.
 *
 * This interface defines the methods that need to be implemented. Implementors
 * are expected to be immutable. That is, they may receive some support data at
 * construction time, but they are not supposed to mutate data inside. Instead,
 * for each receiving message, which should entail a state transition, we should
 * instantiate a new state with the appropriate set of initial data.
 *
 * @author Danny van Heumen
 */
// FIXME implement destroying AuthState data upon transitioning.
public interface AuthState {

    /**
     * Initiate a new AKE. Caller needs to send
     *
     * @param context        Context.
     * @param version        Initiate AKE using protocol version.
     * @param receiverTag    The receiver's instance tag. This tag may not always
     *                       be known at this time, therefore providing ZERO TAG is also valid.
     * @param queryTag       The query tag that was originally received.
     * @return Returns DHCommitMessage with which we can initiate an AKE.
     */
    @Nonnull
    AbstractEncodedMessage initiate(@Nonnull AuthContext context, int version, @Nonnull InstanceTag receiverTag,
            @Nonnull final String queryTag);

    /**
     * Handle AKE message.
     *
     * @param context The current AKE context.
     * @param message The message to be handled.
     * @return Returns message to be injected into the transport stream to
     * continue the AKE process. In case of 'null' no message needs to be
     * injected after handling this message.
     * @throws ProtocolException Throws exception in case of bad message content. (Note that an AbstractEncodedMessage
     * instance is provided, so failures should only occur based on bad message content.)
     * @throws OtrException Throws OtrException in case of unexpected situations during message processing, such as
     * verification and validation exceptions.
     */
    // FIXME verify that now that we transition after handling message completely, that we ensure that we *always* transition also in case some exception occurs while processing the response.
    @Nonnull
    Result handle(@Nonnull AuthContext context, @Nonnull AbstractEncodedMessage message)
            throws ProtocolException, OtrException;

    /**
     * Result of AKE state handling.
     */
    final class Result {
        /**
         * The response to send to the other party, if applicable.
         */
        @Nullable
        public final AbstractEncodedMessage response;

        /**
         * The security parameters on which to base the encrypted session.
         */
        @Nullable
        public final SecurityParameters params;

        Result() {
            this.response = null;
            this.params = null;
        }

        Result(@Nullable final AbstractEncodedMessage response, @Nullable final SecurityParameters params) {
            this.response = response;
            this.params = params;
        }
    }

    /**
     * Get active protocol version in AKE negotiation.
     *
     * Returns a version &gt; 0 in case of an active AKE negotiation in which a
     * protocol version is already negotiated. Returns 0 in case no negotiation
     * is in progress.
     *
     * @return Returns active protocol version in AKE negotiation. (Or 0 if not
     * in progress.)
     */
    int getVersion();
}
