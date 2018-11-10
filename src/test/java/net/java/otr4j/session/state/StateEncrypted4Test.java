package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.SecurityParameters4;
import org.junit.Test;

import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;

import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.session.ake.SecurityParameters4TestUtils.createSecurityParameters4;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("ConstantConditions")
public final class StateEncrypted4Test {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final OtrEngineHost HOST = mock(OtrEngineHost.class);
    private static final SessionID SESSION_ID = new SessionID("me@network", "them@network", "network");
    private static final Context CONTEXT = mock(Context.class);

    static {
        when(CONTEXT.getSessionID()).thenReturn(SESSION_ID);
        when(CONTEXT.getHost()).thenReturn(HOST);
        when(CONTEXT.secureRandom()).thenReturn(RANDOM);
        when(CONTEXT.getReceiverInstanceTag()).thenReturn(SMALLEST_TAG);
    }

    private static final EdDSAKeyPair LONG_TERM_KEY_PAIR = EdDSAKeyPair.generate(RANDOM);
    private static final Point FORGING_PUBLIC_KEY = EdDSAKeyPair.generate(RANDOM).getPublicKey();
    private static final ClientProfile MY_PROFILE = new ClientProfile(SMALLEST_TAG, LONG_TERM_KEY_PAIR.getPublicKey(),
            FORGING_PUBLIC_KEY, singleton(Version.FOUR), null);
    private static final ClientProfile THEIR_PROFILE = new ClientProfile(HIGHEST_TAG,
            EdDSAKeyPair.generate(RANDOM).getPublicKey(), EdDSAKeyPair.generate(RANDOM).getPublicKey(),
            singleton(Version.FOUR), null);

    @Test
    public void testConstructStateEncrypted4() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SecurityParameters4 params = createSecurityParameters4(SecurityParameters4.Component.OURS, ecdhKeyPair,
                dhKeyPair, theirECDHPublicKey, theirDHPublicKey, MY_PROFILE, THEIR_PROFILE);
        new StateEncrypted4(CONTEXT, params);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateEncrypted4NullParams() {
        new StateEncrypted4(CONTEXT, null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateEncrypted4NullContext() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SecurityParameters4 params = createSecurityParameters4(SecurityParameters4.Component.OURS, ecdhKeyPair,
                dhKeyPair, theirECDHPublicKey, theirDHPublicKey, MY_PROFILE, THEIR_PROFILE);
        new StateEncrypted4(null, params);
    }

    @Test(expected = IllegalStateException.class)
    public void testConstructStateEncrypted4HandleNullDataMessage() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SecurityParameters4 params = createSecurityParameters4(SecurityParameters4.Component.OURS, ecdhKeyPair,
                dhKeyPair, theirECDHPublicKey, theirDHPublicKey, MY_PROFILE, THEIR_PROFILE);
        final StateEncrypted4 state = new StateEncrypted4(CONTEXT, params);
        state.handleDataMessage(CONTEXT, (DataMessage) null);
    }

    @Test(expected = IllegalStateException.class)
    public void testConstructStateEncrypted4HandleDataMessageNullContext() {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SecurityParameters4 params = createSecurityParameters4(SecurityParameters4.Component.OURS, ecdhKeyPair,
                dhKeyPair, theirECDHPublicKey, theirDHPublicKey, MY_PROFILE, THEIR_PROFILE);
        final StateEncrypted4 state = new StateEncrypted4(CONTEXT, params);
        state.handleDataMessage(null, (DataMessage) null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateEncrypted4HandleNullDataMessage4() throws OtrException, ProtocolException {
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SecurityParameters4 params = createSecurityParameters4(SecurityParameters4.Component.OURS, ecdhKeyPair,
                dhKeyPair, theirECDHPublicKey, theirDHPublicKey, MY_PROFILE, THEIR_PROFILE);
        final StateEncrypted4 state = new StateEncrypted4(CONTEXT, params);
        state.handleDataMessage(CONTEXT, (DataMessage4) null);
    }
}