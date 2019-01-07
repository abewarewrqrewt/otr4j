package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.SharedSecret4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.StateInitial;
import org.junit.Test;

import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;

import static java.util.Collections.singleton;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
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
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final Point myPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final Point theirPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 sharedSecret = new SharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, sharedSecret, rootKey, DoubleRatchet.Role.ALICE);
        new StateEncrypted4(CONTEXT, ssid, myPublicKey, theirPublicKey, ratchet, StateInitial.instance());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateEncrypted4NullParams() {
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final Point myPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final Point theirPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 sharedSecret = new SharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, sharedSecret, rootKey, DoubleRatchet.Role.ALICE);
        new StateEncrypted4(CONTEXT, null, myPublicKey, theirPublicKey, ratchet, StateInitial.instance());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateEncrypted4NullOurLongTermPublicKey() {
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final Point theirPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 sharedSecret = new SharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, sharedSecret, rootKey, DoubleRatchet.Role.ALICE);
        new StateEncrypted4(CONTEXT, ssid, null, theirPublicKey, ratchet, StateInitial.instance());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateEncrypted4NullTheirrLongTermPublicKey() {
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final Point myPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 sharedSecret = new SharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, sharedSecret, rootKey, DoubleRatchet.Role.ALICE);
        new StateEncrypted4(CONTEXT, ssid, myPublicKey, null, ratchet, StateInitial.instance());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateEncrypted4NullContext() {
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final Point myPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final Point theirPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 sharedSecret = new SharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, sharedSecret, rootKey, DoubleRatchet.Role.ALICE);
        new StateEncrypted4(null, ssid, myPublicKey, theirPublicKey, ratchet, StateInitial.instance());
    }

    @Test(expected = IllegalStateException.class)
    public void testConstructStateEncrypted4HandleNullDataMessage() {
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final Point myPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final Point theirPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 sharedSecret = new SharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, sharedSecret, rootKey, DoubleRatchet.Role.ALICE);
        final StateEncrypted4 state = new StateEncrypted4(CONTEXT, ssid, myPublicKey, theirPublicKey, ratchet,
                StateInitial.instance());
        state.handleDataMessage(CONTEXT, (DataMessage) null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateEncrypted4HandleNullDataMessage4() throws OtrException, ProtocolException {
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final Point myPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final Point theirPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final SharedSecret4 sharedSecret = new SharedSecret4(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(RANDOM, sharedSecret, rootKey, DoubleRatchet.Role.ALICE);
        final StateEncrypted4 state = new StateEncrypted4(CONTEXT, ssid, myPublicKey, theirPublicKey, ratchet,
                StateInitial.instance());
        state.handleDataMessage(CONTEXT, (DataMessage4) null);
    }
}