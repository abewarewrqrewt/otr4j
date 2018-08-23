package net.java.otr4j.session.smpv4;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SmpEngineHost;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import nl.dannyvanheumen.joldilocks.Point;
import org.junit.Test;

import java.net.ProtocolException;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.session.api.SMPStatus.SUCCEEDED;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;
import static net.java.otr4j.util.ByteArrays.toHexString;
import static net.java.otr4j.util.SecureRandoms.random;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public final class SMPTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] ssid = random(RANDOM, new byte[8]);

    private final SessionID sessionIDAlice = new SessionID("alice@localhost", "bob@localhost", "xmpp");
    private final SessionID sessionIDBob = new SessionID("bob@localhost", "alice@localhost", "xmpp");
    private final InstanceTag tagAlice = InstanceTag.random(RANDOM);
    private final InstanceTag tagBob = InstanceTag.random(RANDOM);
    private final Point publicKeyAlice = EdDSAKeyPair.generate(RANDOM).getPublicKey();
    private final Point publicKeyBob = EdDSAKeyPair.generate(RANDOM).getPublicKey();

    @Test
    public void testSMPStraightforwardSuccessful() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = new byte[] {'a', 'l', 'i', 'c', 'e' };
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SmpEngineHost hostBob = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        final SMP smpBob = new SMP(RANDOM, hostBob, sessionIDBob, ssid, publicKeyBob, publicKeyAlice, tagAlice);
        assertEquals(UNDECIDED, smpAlice.getStatus());
        assertEquals(UNDECIDED, smpBob.getStatus());
        final TLV smp1 = smpAlice.initiate(question, answer);
        assertNotNull(smp1);
        assertNull(smpBob.process(smp1));
        verify(hostBob).askForSecret(sessionIDBob, tagAlice, question);
        final TLV smp2 = smpBob.respond(question, answer);
        assertNotNull(smp2);
        final TLV smp3 = smpAlice.process(smp2);
        assertNotNull(smp3);
        final TLV smp4 = smpBob.process(smp3);
        assertNotNull(smp4);
        assertEquals(SUCCEEDED, smpBob.getStatus());
        verify(hostBob).verify(sessionIDBob, toHexString(fingerprint(publicKeyAlice)));
        assertNull(smpAlice.process(smp4));
        assertEquals(SUCCEEDED, smpAlice.getStatus());
        verify(hostAlice).verify(sessionIDAlice, toHexString(fingerprint(publicKeyBob)));
    }
}