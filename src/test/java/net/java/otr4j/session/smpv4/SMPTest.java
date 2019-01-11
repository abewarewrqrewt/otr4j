/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SmpEngineHost;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.session.api.SMPStatus;
import org.junit.Test;
import org.mockito.Matchers;

import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.math.BigInteger.valueOf;
import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Ed448.generateRandomValueInZq;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.session.api.SMPStatus.FAILED;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.api.SMPStatus.SUCCEEDED;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;
import static net.java.otr4j.session.smpv4.SMP.smpPayload;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP1;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP4;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP_ABORT;
import static net.java.otr4j.util.ByteArrays.toHexString;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored"})
public final class SMPTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] ssid = randomBytes(RANDOM, new byte[8]);

    private final SessionID sessionIDAlice = new SessionID("alice@localhost", "bob@localhost", "xmpp");
    private final SessionID sessionIDBob = new SessionID("bob@localhost", "alice@localhost", "xmpp");
    private final InstanceTag tagAlice = InstanceTag.random(RANDOM);
    private final InstanceTag tagBob = InstanceTag.random(RANDOM);
    private final Point publicKeyAlice = EdDSAKeyPair.generate(RANDOM).getPublicKey();
    private final Point publicKeyBob = EdDSAKeyPair.generate(RANDOM).getPublicKey();

    @Test
    public void testSMPStraightforwardSuccessful() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = new byte[] {'a', 'l', 'i', 'c', 'e'};
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

    @Test
    public void testSMPSuccessfulVeryLargeSecret() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = randomBytes(RANDOM, new byte[16384]);
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

    @Test
    public void testSMPMissingQuestionSuccessful() throws OtrCryptoException, ProtocolException {
        final byte[] answer = randomBytes(RANDOM, new byte[16384]);
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SmpEngineHost hostBob = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        final SMP smpBob = new SMP(RANDOM, hostBob, sessionIDBob, ssid, publicKeyBob, publicKeyAlice, tagAlice);
        assertEquals(UNDECIDED, smpAlice.getStatus());
        assertEquals(UNDECIDED, smpBob.getStatus());
        final TLV smp1 = smpAlice.initiate("", answer);
        assertNotNull(smp1);
        assertNull(smpBob.process(smp1));
        verify(hostBob).askForSecret(sessionIDBob, tagAlice, "");
        final TLV smp2 = smpBob.respond("", answer);
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

    @Test
    public void testSMPFailsBadAnswer() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SmpEngineHost hostBob = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        final SMP smpBob = new SMP(RANDOM, hostBob, sessionIDBob, ssid, publicKeyBob, publicKeyAlice, tagAlice);
        assertEquals(UNDECIDED, smpAlice.getStatus());
        assertEquals(UNDECIDED, smpBob.getStatus());
        final TLV smp1 = smpAlice.initiate(question, new byte[] {'a', 'l', 'i', 'c', 'e'});
        assertNotNull(smp1);
        assertNull(smpBob.process(smp1));
        verify(hostBob).askForSecret(sessionIDBob, tagAlice, question);
        final TLV smp2 = smpBob.respond(question, new byte[] {'b', 'o', 'b'});
        assertNotNull(smp2);
        final TLV smp3 = smpAlice.process(smp2);
        assertNotNull(smp3);
        final TLV smp4 = smpBob.process(smp3);
        assertNotNull(smp4);
        assertEquals(FAILED, smpBob.getStatus());
        verify(hostBob).unverify(sessionIDBob, toHexString(fingerprint(publicKeyAlice)));
        assertNull(smpAlice.process(smp4));
        assertEquals(FAILED, smpAlice.getStatus());
        verify(hostAlice).unverify(sessionIDAlice, toHexString(fingerprint(publicKeyBob)));
    }

    @Test
    public void testSMPFailsBadSSID() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = new byte[] {'a', 'l', 'i', 'c', 'e'};
        final byte[] ssid1 = randomBytes(RANDOM, new byte[8]);
        final byte[] ssid2 = randomBytes(RANDOM, new byte[8]);
        assumeTrue("With all the luck in the world, the same ssid is generated randomly twice.",
                !Arrays.equals(ssid1, ssid2));
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SmpEngineHost hostBob = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid1, publicKeyAlice, publicKeyBob, tagBob);
        final SMP smpBob = new SMP(RANDOM, hostBob, sessionIDBob, ssid2, publicKeyBob, publicKeyAlice, tagAlice);
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
        assertEquals(FAILED, smpBob.getStatus());
        verify(hostBob).unverify(sessionIDBob, toHexString(fingerprint(publicKeyAlice)));
        assertNull(smpAlice.process(smp4));
        assertEquals(FAILED, smpAlice.getStatus());
        verify(hostAlice).unverify(sessionIDAlice, toHexString(fingerprint(publicKeyBob)));
    }

    @Test
    public void testSMPAbortsRunningSMP() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = new byte[] {'a', 'l', 'i', 'c', 'e'};
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
        final TLV abortTLV = smpAlice.initiate(question, answer);
        assertEquals(SMP_ABORT, abortTLV.getType());
        final TLV initTLV = smpAlice.initiate(question, answer);
        assertEquals(SMP1, initTLV.getType());
    }

    @Test
    public void testSMPRespondBeforeSMP1() {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = new byte[] {'a', 'l', 'i', 'c', 'e'};
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        assertEquals(UNDECIDED, smpAlice.getStatus());
        assertNull(smpAlice.respond(question, answer));
    }

    @Test
    public void testSMPRespondDifferentQuestion() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = new byte[] {'a', 'l', 'i', 'c', 'e'};
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
        assertNull(smpBob.respond("Responding to different question.", answer));
    }

    @Test
    public void testSMPProcessAbortTLV() throws OtrCryptoException, ProtocolException {
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        assertEquals(UNDECIDED, smpAlice.getStatus());
        assertNull(smpAlice.process(new TLV(SMP_ABORT, new byte[0])));
    }

    @Test
    public void testSMPProcessAbortTLVInProgress() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = new byte[] {'a', 'l', 'i', 'c', 'e'};
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        assertEquals(UNDECIDED, smpAlice.getStatus());
        assertNotNull(smpAlice.initiate(question, answer));
        assertEquals(INPROGRESS, smpAlice.getStatus());
        assertNull(smpAlice.process(new TLV(SMP_ABORT, new byte[0])));
        assertEquals(UNDECIDED, smpAlice.getStatus());
    }

    @Test
    public void testSMPUnexpectedTLVAborts() throws OtrCryptoException, ProtocolException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final byte[] answer = new byte[] {'a', 'l', 'i', 'c', 'e'};
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        assertEquals(UNDECIDED, smpAlice.getStatus());
        assertNotNull(smpAlice.initiate(question, answer));
        assertEquals(INPROGRESS, smpAlice.getStatus());
        final byte[] tlvPayload = encode(new SMPMessage4(basePoint(), generateRandomValueInZq(RANDOM),
                generateRandomValueInZq(RANDOM)));
        final TLV abortTLV = smpAlice.process(new TLV(SMP4, tlvPayload));
        assertEquals(SMP_ABORT, abortTLV.getType());
        assertEquals(UNDECIDED, smpAlice.getStatus());
    }

    @Test(expected = IllegalStateException.class)
    public void testSMPUnexpectedSMPMessageProcessingResult() throws OtrCryptoException, ProtocolException, SMPAbortException {
        final String question = "Who am I? (I know it's a lousy question ...)";
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        final SMPState badSMPState = mock(SMPState.class);
        final Point g2a = basePoint().multiply(fromBigInteger(valueOf(2L)));
        final Scalar c2 = generateRandomValueInZq(RANDOM);
        final Scalar d2 = generateRandomValueInZq(RANDOM);
        final Scalar c3 = generateRandomValueInZq(RANDOM);
        final Scalar d3 = generateRandomValueInZq(RANDOM);
        final Point g3a = basePoint().multiply(fromBigInteger(valueOf(3L)));
        final SMPMessage1 illegalMessage = new SMPMessage1(question, g2a, c2, d2, g3a, c3, d3);
        when(badSMPState.getStatus()).thenReturn(SMPStatus.INPROGRESS);
        when(badSMPState.process(Matchers.eq(smpAlice), any(SMPMessage.class))).thenReturn(illegalMessage);
        smpAlice.setState(badSMPState);
        final byte[] tlvPayload = encode(new SMPMessage4(basePoint(), generateRandomValueInZq(RANDOM),
                generateRandomValueInZq(RANDOM)));
        smpAlice.process(new TLV(SMP4, tlvPayload));
    }

    @Test
    public void testSMPRepeatedClosingAllowed() {
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        smpAlice.close();
        smpAlice.close();
    }

    @Test
    public void testSmpAbortedTLVCheck() {
        final SmpEngineHost hostAlice = mock(SmpEngineHost.class);
        final SMP smpAlice = new SMP(RANDOM, hostAlice, sessionIDAlice, ssid, publicKeyAlice, publicKeyBob, tagBob);
        final TLV initSMP = smpAlice.initiate("Hello world", new byte[10]);
        final TLV abortTLV = smpAlice.abort();
        assertFalse(smpAlice.smpAbortedTLV(initSMP));
        assertTrue(smpAlice.smpAbortedTLV(abortTLV));
    }

    @Test(expected = NullPointerException.class)
    public void testSmpTlvNull() {
        smpPayload(null);
    }

    @Test
    public void testSmpTlvVerifyAllSMPTLVs() {
        assertFalse("TLV type 0", smpPayload(new TLV(0, new byte[0])));
        assertFalse("TLV type 1", smpPayload(new TLV(1, new byte[0])));
        for (int i = 2; i < 7; i++) {
            assertTrue("TLV type " + i, smpPayload(new TLV(i, new byte[0])));
        }
        for (int i = 7; i < 200; i++) {
            assertFalse("TLV type " + i, smpPayload(new TLV(i, new byte[0])));
        }
    }
}