/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.Message;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.StateInitial;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.reflection.Whitebox;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;

import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.session.state.DoubleRatchet.Role.ALICE;
import static net.java.otr4j.session.state.State.FLAG_IGNORE_UNREADABLE;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, sharedSecret, rootKey);
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
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, sharedSecret, rootKey);
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
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, sharedSecret, rootKey);
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
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, sharedSecret, rootKey);
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
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, sharedSecret, rootKey);
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
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, sharedSecret, rootKey);
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
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, sharedSecret, rootKey);
        final StateEncrypted4 state = new StateEncrypted4(CONTEXT, ssid, myPublicKey, theirPublicKey, ratchet,
                StateInitial.instance());
        state.handleDataMessage(CONTEXT, (DataMessage4) null);
    }

    @Test
    public void testExpiringSessionSendsDisconnectMessageWithTLV() throws OtrException {
        final ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final Context context = mock(Context.class);
        when(context.getSessionID()).thenReturn(new SessionID("bob", "network", "alice"));
        when(context.secureRandom()).thenReturn(RANDOM);
        when(context.getHost()).thenReturn(host);
        final InstanceTag senderTag = InstanceTag.random(RANDOM);
        when(context.getSenderInstanceTag()).thenReturn(senderTag);
        final InstanceTag receiverTag = InstanceTag.random(RANDOM);
        when(context.getReceiverInstanceTag()).thenReturn(receiverTag);
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        final Point myPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final Point theirPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final DoubleRatchet ratchet = new DoubleRatchet(ALICE, sharedSecret, rootKey);

        // Test StateEncrypted4 expiring
        final byte[] artificialMACsToReveal = randomBytes(RANDOM, new byte[120]);
        ((ByteArrayOutputStream) Whitebox.getInternalState(ratchet, "macsToReveal")).write(artificialMACsToReveal, 0,
                artificialMACsToReveal.length);
        final StateEncrypted4 state = new StateEncrypted4(context, ssid, myPublicKey, theirPublicKey, ratchet,
                StateInitial.instance());
        state.expire(context);

        // Verify that state is correct after expiring.
        verify(context, times(1)).injectMessage(captor.capture());
        verify(context, times(1)).transition(eq(state), any(StatePlaintext.class));
        final DataMessage4 disconnectMessage = (DataMessage4) captor.getValue();
        assertEquals(FLAG_IGNORE_UNREADABLE, disconnectMessage.flags & FLAG_IGNORE_UNREADABLE);
        assertTrue(disconnectMessage.ciphertext.length > 1);
        assertArrayEquals(artificialMACsToReveal, disconnectMessage.revealedMacs);
        assertArrayEquals(new byte[0], ratchet.collectRemainingMACsToReveal());
    }

    @Test
    public void testExpireStateEncrypted4ToFinished() throws OtrException {
        final Context context = mock(Context.class);
        when(context.getSessionID()).thenReturn(new SessionID("bob", "alice", "network"));
        when(context.getSenderInstanceTag()).thenReturn(InstanceTag.random(RANDOM));
        when(context.getReceiverInstanceTag()).thenReturn(InstanceTag.random(RANDOM));
        when(context.secureRandom()).thenReturn(RANDOM);
        when(context.getHost()).thenReturn(mock(OtrEngineHost.class));
        final byte[] ssid = randomBytes(RANDOM, new byte[8]);
        final byte[] rootKey = randomBytes(RANDOM, new byte[64]);
        final Point myPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final Point theirPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ECDHKeyPair ecdhKeyPair = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dhKeyPair = DHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final MixedSharedSecret sharedSecret = new MixedSharedSecret(RANDOM, dhKeyPair, ecdhKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        final DoubleRatchet ratchet = new DoubleRatchet(sharedSecret, rootKey, DoubleRatchet.Role.ALICE);
        final StateEncrypted4 current = new StateEncrypted4(context, ssid, myPublicKey, theirPublicKey, ratchet, StateInitial.instance());
        current.expire(context);
        verify(context, times(1)).transition(eq(current), isA(StateFinished.class));
    }
}