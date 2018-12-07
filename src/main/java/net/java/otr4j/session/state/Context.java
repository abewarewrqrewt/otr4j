/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.io.Message;
import net.java.otr4j.messages.ClientProfilePayload;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

/**
 * Session state context.
 *
 * Context of the session as used by the session state implementations.
 *
 * @author Danny van Heumen
 */
public interface Context {

    /**
     * Get engine host instance.
     *
     * @return Returns instance.
     */
    @Nonnull
    OtrEngineHost getHost();

    /**
     * Get protocol version of session context.
     *
     * @return Returns version of OTR, or 0 if session is not secured.
     */
    int getProtocolVersion();

    /**
     * Inject message into IM transport channel.
     *
     * @param msg message
     * @throws OtrException Throws in case of problems while injecting message.
     */
    void injectMessage(@Nonnull Message msg) throws OtrException;

    /**
     * Get ID of current session.
     *
     * @return Returns session ID.
     */
    @Nonnull
    SessionID getSessionID();

    /**
     * Get the current status.
     *
     * @return Returns session status.
     */
    SessionStatus getSessionStatus();

    /**
     * Get session policy.
     *
     * @return Returns session policy.
     */
    @Nonnull
    OtrPolicy getSessionPolicy();

    /**
     * Transition to a new session state.
     * <p>
     * As part of setting the new state, the current state is being verified. If the provided 'fromState' argument is
     * not the current state, transitioning is not allowed. This is a sanity check to ensure that we are not operating
     * on bad assumptions.
     * <p>
     * Upon calling this method it is assumed that the #toState instance is fully initiated and operational. Immediately
     * after transitioning, the fromState instance will be {@link State#destroy()}ed. This also requires that the old
     * and new state cannot share any data that is clearable, as it will be cleared as part of destroying the old state.
     *
     * @param fromState the current state instance - will be cleared after transitioning
     * @param toState   the new state instance - will become current after transitioning
     */
    void transition(@Nonnull State fromState, @Nonnull State toState);

    /**
     * Get sender (our) instance tag.
     *
     * @return Returns sender instance tag.
     */
    @Nonnull
    InstanceTag getSenderInstanceTag();

    /**
     * Get receiver (their) instance tag.
     *
     * @return Returns receiver instance tag.
     */
    @Nonnull
    InstanceTag getReceiverInstanceTag();

    /**
     * Get the OTR-encodable payload of the client profile.
     *
     * @return Returns the OTR-encodable payload.
     */
    @Nonnull
    ClientProfilePayload getClientProfilePayload();

    /**
     * Session's secure random instance.
     *
     * @return Returns secure random instance.
     */
    @Nonnull
    SecureRandom secureRandom();

    /**
     * Get status white-space OTR offer.
     *
     * @return Returns offer status.
     */
    @Nonnull
    OfferStatus getOfferStatus();

    /**
     * Set offer status to sent.
     */
    void setOfferStatusSent();

    String getQueryTag();

    /**
     * Get the master session to which the instance belongs.
     *
     * @return Returns master session instance, may be itself ("{@code this}").
     */
    @Nonnull
    Session getMasterSession();

    /**
     * Start OTR session.
     *
     * @throws OtrException Throws in case of problems during start.
     */
    void startSession() throws OtrException;
}
