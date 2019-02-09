/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.session.state.State;
import org.junit.Test;
import org.mockito.internal.util.reflection.Whitebox;

import java.security.SecureRandom;

import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("ConstantConditions")
public final class SessionImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = IllegalArgumentException.class)
    public void testTransitionFromNullState() {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), forgingKey,
                singleton(Version.FOUR), null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getClientProfile(eq(sessionID))).thenReturn(profile);
        final SessionImpl session = new SessionImpl(sessionID, host);
        session.transition(null, mock(State.class));
    }

    @Test(expected = NullPointerException.class)
    public void testTransitionToNullState() {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), forgingKey,
                singleton(Version.FOUR), null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getClientProfile(eq(sessionID))).thenReturn(profile);
        final SessionImpl session = new SessionImpl(sessionID, host);
        session.transition((State) Whitebox.getInternalState(session, "sessionState"), null);
    }

    @Test
    public void testTransitionDestroysPreviousState() {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), forgingKey,
                singleton(Version.FOUR), null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getClientProfile(eq(sessionID))).thenReturn(profile);
        final SessionImpl session = new SessionImpl(sessionID, host);
        final State secondState = mock(State.class);
        session.transition((State) Whitebox.getInternalState(session, "sessionState"), secondState);
        verify(secondState, times(0)).destroy();
        session.transition(secondState, mock(State.class));
        verify(secondState, times(1)).destroy();
    }

    @Test
    public void testTransitionToSecureSessionCallsSessionStatusChanged() {
        final EdDSAKeyPair longTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point forgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final SessionID sessionID = new SessionID("bob@network", "alice@network", "network");
        final ClientProfile profile = new ClientProfile(SMALLEST_TAG, longTermKeyPair.getPublicKey(), forgingKey,
                singleton(Version.FOUR), null);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(longTermKeyPair);
        when(host.getClientProfile(eq(sessionID))).thenReturn(profile);
        final SessionImpl session = new SessionImpl(sessionID, host);
        final OtrEngineListener listener = mock(OtrEngineListener.class);
        session.addOtrEngineListener(listener);
        final State secondState = mock(State.class);
        when(secondState.getStatus()).thenReturn(ENCRYPTED);
        session.transition((State) Whitebox.getInternalState(session, "sessionState"), secondState);
        // Testing with master session here for simplicity, so not completely representative, but does confirm that
        // sessionStatusChanged is called.
        verify(listener, times(1)).sessionStatusChanged(eq(sessionID), eq(ZERO_TAG));
    }
}