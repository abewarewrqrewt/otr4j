/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smp;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import org.junit.Test;

import javax.annotation.Nonnull;

/**
 * Tests for Socialist Millionaire Protocol.
 *
 * @author Danny van Heumen
 */
public class SMTest {
    
    private final SecureRandom sr = new SecureRandom();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @SuppressWarnings({"ThrowableInstanceNotThrown", "ThrowableInstanceNeverThrown", "ResultOfObjectAllocationIgnored"})
    public void testConstructSMException() {
        new SMException("Test");
    }

    @Test
    public void testConstructSMExceptionMessage() {
        final SMException e = new SMException("Hello world!");
        assertEquals("Hello world!", e.getMessage());
    }

    @Test
    public void testConstructSMExceptionThrowable() {
        @SuppressWarnings({"ThrowableInstanceNotThrown", "ThrowableInstanceNeverThrown"})
        final Throwable t = new Throwable("bad stuff happened");
        final SMException e = new SMException(t);
        assertSame(t, e.getCause());
    }

    @Test
    public void testConstructSMExceptionMessageThrowable() {
        @SuppressWarnings({"ThrowableInstanceNotThrown", "ThrowableInstanceNeverThrown"})
        final Throwable t = new Throwable("bad stuff happened");
        final SMException e = new SMException("Hello world!", t);
        assertEquals("Hello world!", e.getMessage());
        assertSame(t, e.getCause());
    }

    @Test
    @SuppressWarnings({"ThrowableInstanceNotThrown", "ThrowableInstanceNeverThrown", "ResultOfObjectAllocationIgnored"})
    public void testAbortedException() {
        final SMAbortedException e = new SMAbortedException(false, "Stuff was aborted!");
        assertFalse(e.isInProgress());
        assertEquals("Stuff was aborted!", e.getMessage());
    }

    @Test
    public void testCheckGroupElemValid() throws SMException {
        AbstractSMPState.checkGroupElem(BigInteger.TEN);
    }

    @Test
    public void testCheckGroupElemJustValidLowerBound() throws SMException {
        AbstractSMPState.checkGroupElem(BigInteger.valueOf(2l));
    }

    @Test(expected = SMException.class)
    public void testCheckGroupElemTooSmall() throws SMException {
        AbstractSMPState.checkGroupElem(BigInteger.ONE);
    }

    @Test
    public void testCheckGroupElemJustValidUpperBound() throws SMException {
        AbstractSMPState.checkGroupElem(OtrCryptoEngine.MODULUS_MINUS_TWO);
    }

    @Test(expected = SMException.class)
    public void testCheckGroupElemTooLarge() throws SMException {
        AbstractSMPState.checkGroupElem(OtrCryptoEngine.MODULUS_MINUS_TWO.add(BigInteger.ONE));
    }

    @Test
    public void testCheckExponValid() throws SMException {
        AbstractSMPState.checkExpon(BigInteger.TEN);
    }

    @Test
    public void testCheckExponJustValidLowerBound() throws SMException {
        AbstractSMPState.checkExpon(BigInteger.ONE);
    }

    @Test(expected = SMException.class)
    public void testCheckExponTooSmall() throws SMException {
        AbstractSMPState.checkExpon(BigInteger.ZERO);
    }

    @Test
    public void testCheckExponJustValidUpperBound() throws SMException {
        AbstractSMPState.checkExpon(AbstractSMPState.ORDER_S.subtract(BigInteger.ONE));
    }

    @Test(expected = SMException.class)
    public void testCheckExponTooLarge() throws SMException {
        AbstractSMPState.checkExpon(AbstractSMPState.ORDER_S);
    }

    @Test(expected = SMException.class)
    public void testCheckKnowLog() throws SMException {
        final AbstractSMPState sm = new AbstractSMPState(sr) {
            @Override
            SMPStatus status() {
                return SMPStatus.UNDECIDED;
            }
        };
        sm.checkKnowLog(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, 0);
    }

    @Test(expected = SMException.class)
    public void testCheckEqualCoords() throws SMException {
        final AbstractSMPState sm = new AbstractSMPState(sr) {
            @Override
            SMPStatus status() {
                return SMPStatus.UNDECIDED;
            }
        };
        sm.checkEqualCoords(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(100L), BigInteger.valueOf(50L), BigInteger.valueOf(25L), BigInteger.valueOf(12L), 0);
    }

    @Test(expected = SMException.class)
    public void testCheckEqualLogs() throws SMException {
        final AbstractSMPState sm = new AbstractSMPState(sr) {
            @Override
            SMPStatus status() {
                return SMPStatus.UNDECIDED;
            }
        };
        sm.checkEqualLogs(BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO, BigInteger.valueOf(23L), BigInteger.valueOf(35L), 0);
    }

    @Test
    public void testUnserializeSerializedBigIntArray() throws SMException {
        final BigInteger[] target = new BigInteger[] {
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.valueOf(125L),
            BigInteger.valueOf(2500000L),
        };
        assertArrayEquals(target, SM.unserialize(SM.serialize(target)));
    }

    @Test
    public void testUnserializeZeroLength() throws SMException {
        final byte[] data = new byte[] { 0, 0, 0, 0 };
        final BigInteger[] result = SM.unserialize(data);
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test(expected = SMException.class)
    public void testUnserializeLargeSignedLength() throws SMException {
        final byte[] data = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
        SM.unserialize(data);
    }

    @Test(expected = NullPointerException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructionNullSecureRandom() {
        new SM(null);
    }

    @Test
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructionWithValidSecureRandom() {
        new SM(sr);
    }

    @Test
    public void testSuccessfulSMPConversation() throws SMException, OtrCryptoException, Exception {

        // Alice
        final SM alice = new SM(sr);
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());

        // Bob
        final SM bob = new SM(sr);
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Shared secret
        final byte[] secret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final SharedSecret s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytes = combinedSecret(alicePublic, bobPublic, s, secret);

        // SMP session execution
        assertEquals(SMPStatus.UNDECIDED, alice.status());
        assertEquals(SMPStatus.UNDECIDED, bob.status());

        final byte[] msg1 = alice.step1(combinedSecretBytes);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.UNDECIDED, bob.status());

        bob.step2a(msg1);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.INPROGRESS, bob.status());

        final byte[] msg2 = bob.step2b(combinedSecretBytes);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.INPROGRESS, bob.status());

        final byte[] msg3 = alice.step3(msg2);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.INPROGRESS, bob.status());

        final byte[] msg4 = bob.step4(msg3);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.SUCCEEDED, bob.status());

        alice.step5(msg4);
        // Evaluate session end result
        assertEquals(SMPStatus.SUCCEEDED, alice.status());
        assertEquals(SMPStatus.SUCCEEDED, bob.status());
    }

    @Test
    public void testUnsuccessfulSMPConversationBadSecret() throws SMException, OtrCryptoException, Exception {

        // Alice
        final SM alice = new SM(sr);
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());

        // Bob
        final SM bob = new SM(sr);
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Shared secret
        final byte[] aliceSecret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final byte[] bobSecret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 't' };
        final SharedSecret s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytesAlice = combinedSecret(alicePublic, bobPublic, s, aliceSecret);
        final byte[] combinedSecretBytesBob = combinedSecret(alicePublic, bobPublic, s, bobSecret);

        // SMP session execution
        assertEquals(SMPStatus.UNDECIDED, alice.status());
        assertEquals(SMPStatus.UNDECIDED, bob.status());

        final byte[] msg1 = alice.step1(combinedSecretBytesAlice);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.UNDECIDED, bob.status());

        bob.step2a(msg1);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.INPROGRESS, bob.status());

        final byte[] msg2 = bob.step2b(combinedSecretBytesBob);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.INPROGRESS, bob.status());

        final byte[] msg3 = alice.step3(msg2);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.INPROGRESS, bob.status());

        final byte[] msg4 = bob.step4(msg3);
        assertEquals(SMPStatus.INPROGRESS, alice.status());
        assertEquals(SMPStatus.FAILED, bob.status());

        alice.step5(msg4);
        // Evaluate session end result
        assertEquals(SMPStatus.FAILED, alice.status());
        assertEquals(SMPStatus.FAILED, bob.status());
    }

    @Test
    public void testVerifyCorrectSpecifiedStatusStateExpect1() {
        assertEquals(SMPStatus.FAILED, new StateExpect1(sr, SMPStatus.FAILED).status());
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect1CorrectlyAbortOnAnswerBeforeQuestion() throws SMException {
        final SM sm = new SM(sr);
        sm.step2b(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect1CorrectlyAbortOnMessage2() throws SMException {
        final SM sm = new SM(sr);
        sm.step3(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect1CorrectlyAbortOnMessage3() throws SMException {
        final SM sm = new SM(sr);
        sm.step4(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect1CorrectlyAbortOnMessage4() throws SMException {
        final SM sm = new SM(sr);
        sm.step5(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnInit() throws SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step1(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnMessage1() throws SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step2a(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnMessage1Continuation() throws SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step2b(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnMessage3() throws SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step4(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect2CorrectlyAbortOnMessage4() throws SMException {
        final SM sm = new SM(sr);
        sm.setState(new StateExpect2(sr, BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE));
        sm.step5(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect3CorrectlyAbortOnInit() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        final SM sm = prepareStateExpect3();
        sm.step1(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect3CorrectlyAbortOnMessage1() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        final SM sm = prepareStateExpect3();
        sm.step2a(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect3CorrectlyAbortOnMessage1Continuation() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        final SM sm = prepareStateExpect3();
        sm.step2b(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect3CorrectlyAbortOnMessage4() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        final SM sm = prepareStateExpect3();
        sm.step5(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnInit() throws NoSuchProviderException, OtrCryptoException, SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step1(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnMessage1() throws NoSuchProviderException, OtrCryptoException, SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step2a(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnMessage1Continuation() throws NoSuchProviderException, OtrCryptoException, SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step2b(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnMessage2() throws NoSuchProviderException, OtrCryptoException, SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step3(new byte[0]);
    }

    @Test(expected = SMAbortedException.class)
    public void testVerifyStateExpect4CorrectlyAbortOnMessage3() throws NoSuchProviderException, OtrCryptoException, SMException, Exception {
        final SM sm = prepareStateExpect4();
        sm.step4(new byte[0]);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructStateWithNullSecureRandom() {
        new AbstractSMPState(null) {
            @Override
            @Nonnull
            SMPStatus status() {
                return SMPStatus.UNDECIDED;
            }
        };
    }

    @Test
    public void testSMStep2aWithSMException() throws SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            void smpMessage1a(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            @Nonnull
            SMPStatus status() {
                return SMPStatus.UNDECIDED;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step2a(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep2aWithRuntimeException() throws SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            void smpMessage1a(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            @Nonnull
            SMPStatus status() {
                return SMPStatus.UNDECIDED;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step2a(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep2bWithSMException() throws SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            byte[] smpMessage1b(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            SMPStatus status() {
                return SMPStatus.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step2b(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep2bWithRuntimeException() throws SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            byte[] smpMessage1b(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            SMPStatus status() {
                return SMPStatus.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step2b(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep3WithSMException() throws SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            byte[] smpMessage2(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            SMPStatus status() {
                return SMPStatus.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step3(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep3WithRuntimeException() throws SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            byte[] smpMessage2(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            SMPStatus status() {
                return SMPStatus.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step3(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep4WithSMException() throws SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            byte[] smpMessage3(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            SMPStatus status() {
                return SMPStatus.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step4(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep4WithRuntimeException() throws SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            byte[] smpMessage3(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            SMPStatus status() {
                return SMPStatus.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step4(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep5WithSMException() throws SMException {
        final byte[] input = new byte[0];
        final SMException e = new SMException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            void smpMessage4(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            SMPStatus status() {
                return SMPStatus.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step5(input);
        }
        catch (SMException ex) {
            assertSame(e, ex);
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    @Test
    public void testSMStep5WithRuntimeException() throws SMException {
        final byte[] input = new byte[0];
        final IllegalArgumentException e = new IllegalArgumentException("intentionally bad");
        final AbstractSMPState s = new AbstractSMPState(sr) {

            @Override
            void smpMessage4(SM bstate, byte[] input) throws SMAbortedException, SMException {
                throw e;
            }

            @Override
            SMPStatus status() {
                return SMPStatus.INPROGRESS;
            }
        };
        final SM sm = new SM(sr);
        sm.setState(s);
        // prepare throwing exception on processing
        try {
            sm.step5(input);
        }
        catch (SMException ex) {
            assertSame(e, ex.getCause());
        }
        assertEquals(SMPStatus.CHEATED, sm.status());
    }

    private SM prepareStateExpect4() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        // Alice
        final SM alice = new SM(sr);
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());
        // Bob
        final SM bob = new SM(sr);
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Prepare sm instance for StateExpect3.
        final byte[] secret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final SharedSecret s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytes = combinedSecret(alicePublic, bobPublic, s, secret);
        final byte[] msg1 = alice.step1(combinedSecretBytes);
        bob.step2a(msg1);
        final byte[] msg2 = bob.step2b(combinedSecretBytes);
        alice.step3(msg2);
        return alice;
    }

    private SM prepareStateExpect3() throws NoSuchAlgorithmException, NoSuchProviderException, OtrCryptoException, Exception {
        // Alice
        final SM alice = new SM(sr);
        final KeyPair aliceKeyPair = generateKeyPair();
        final KeyPair aliceDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] alicePublic = OtrCryptoEngine.getFingerprintRaw(aliceKeyPair.getPublic());
        // Bob
        final SM bob = new SM(sr);
        final KeyPair bobKeyPair = generateKeyPair();
        final KeyPair bobDHKeyPair = OtrCryptoEngine.generateDHKeyPair(sr);
        final byte[] bobPublic = OtrCryptoEngine.getFingerprintRaw(bobKeyPair.getPublic());

        // Prepare sm instance for StateExpect3.
        final byte[] secret = new byte[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
        final SharedSecret s = OtrCryptoEngine.generateSecret(aliceDHKeyPair.getPrivate(), bobDHKeyPair.getPublic());
        final byte[] combinedSecretBytes = combinedSecret(alicePublic, bobPublic, s, secret);
        final byte[] msg1 = alice.step1(combinedSecretBytes);
        bob.step2a(msg1);
        bob.step2b(combinedSecretBytes);
        return bob;
    }

    private byte[] combinedSecret(final byte[] alicePublic, final byte[] bobPublic, final SharedSecret s, final byte[] secret) throws Exception {
        final byte[] sessionBytes = s.ssid();
        final byte[] combinedSecret = new byte[1 + alicePublic.length + bobPublic.length + sessionBytes.length + secret.length];
        combinedSecret[0] = 1;
        System.arraycopy(alicePublic, 0, combinedSecret, 1, alicePublic.length);
        System.arraycopy(bobPublic, 0, combinedSecret, 1+alicePublic.length, bobPublic.length);
        System.arraycopy(sessionBytes, 0, combinedSecret, 1+alicePublic.length+bobPublic.length, sessionBytes.length);
        System.arraycopy(secret, 0, combinedSecret, 1+alicePublic.length+bobPublic.length+sessionBytes.length, secret.length);
        return MessageDigest.getInstance("SHA-256").digest(combinedSecret);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA", "BC");
        return kg.genKeyPair();
    }
}