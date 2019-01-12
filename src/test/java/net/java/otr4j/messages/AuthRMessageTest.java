/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Collections;

import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class AuthRMessageTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DSAKeyPair DSA_KEYPAIR = DSAKeyPair.generateDSAKeyPair();

    private static final Point FORGING_KEY = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final EdDSAKeyPair ED_DSA_KEYPAIR = EdDSAKeyPair.generate(RANDOM);

    private static final Point X = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final BigInteger A = DHKeyPair.generate(RANDOM).getPublicKey();

    private static final Point FIRST_ECDH_PUBLIC_KEY = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final BigInteger FIRST_DH_PUBLIC_KEY = DHKeyPair.generate(RANDOM).getPublicKey();

    private static final ClientProfilePayload PAYLOAD = ClientProfilePayload.sign(
            new ClientProfile(SMALLEST_TAG, ED_DSA_KEYPAIR.getPublicKey(), FORGING_KEY,
                    Collections.singleton(Session.Version.FOUR), DSA_KEYPAIR.getPublic()),
            Long.MAX_VALUE / 1000, DSA_KEYPAIR, ED_DSA_KEYPAIR);

    @Test
    public void testConstruction() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        final AuthRMessage message = new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A,
                sigma, FIRST_ECDH_PUBLIC_KEY, FIRST_DH_PUBLIC_KEY);
        assertEquals(Session.Version.FOUR, message.protocolVersion);
        assertEquals(SMALLEST_TAG, message.senderInstanceTag);
        assertEquals(HIGHEST_TAG, message.receiverInstanceTag);
        assertEquals(PAYLOAD, message.clientProfile);
        assertEquals(X, message.x);
        assertEquals(A, message.a);
        assertEquals(FIRST_ECDH_PUBLIC_KEY, message.ourFirstECDHPublicKey);
        assertEquals(FIRST_DH_PUBLIC_KEY, message.ourFirstDHPublicKey);
        assertEquals(sigma, message.sigma);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalProtocolVersionOne() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.ONE, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, sigma, FIRST_ECDH_PUBLIC_KEY,
                FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalProtocolVersionTwo() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.TWO, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, sigma, FIRST_ECDH_PUBLIC_KEY,
                FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalProtocolVersionThree() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.THREE, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, sigma, FIRST_ECDH_PUBLIC_KEY,
                FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullSenderTag() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.FOUR, null, HIGHEST_TAG, PAYLOAD, X, A, sigma,
                FIRST_ECDH_PUBLIC_KEY, FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullReceiverTag() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Version.FOUR, SMALLEST_TAG, null, PAYLOAD, X, A, sigma, FIRST_ECDH_PUBLIC_KEY,
                FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullClientProfilePayload() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, null, X, A, sigma,
                FIRST_ECDH_PUBLIC_KEY, FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullX() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, null, A, sigma,
                FIRST_ECDH_PUBLIC_KEY, FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullA() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, null, sigma, FIRST_ECDH_PUBLIC_KEY,
                FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullSigma() {
        new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, null,
                FIRST_ECDH_PUBLIC_KEY, FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullFirstECDH() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, sigma,
                null, FIRST_DH_PUBLIC_KEY);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullFirstDH() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, null,
                FIRST_ECDH_PUBLIC_KEY, null);
    }

    @Test
    public void testEncodeMessage() throws ProtocolException, OtrCryptoException, ValidationException {
//        final ClientProfilePayload payload = PAYLOAD;
        final ClientProfilePayload payload = ClientProfilePayload.readFrom(new OtrInputStream(new byte[] {0, 0, 0, 7, 0, 1, 0, 0, 1, 0, 0, 2, 0, 16, -4, -1, 65, 16, 17, 125, 35, 111, -70, -94, -74, 59, -24, -56, -32, 62, -123, 30, -7, -99, -26, -72, -4, -77, 0, 58, -58, 51, -105, 95, -103, 122, 91, 7, -88, -127, 7, 10, -107, 68, 21, 96, -89, -126, 19, 41, -74, 35, -32, 54, 63, 79, 31, -90, 84, -121, 0, 0, 3, 0, 18, 21, -67, -71, -17, 53, 127, -42, -126, 27, -115, 54, -89, -51, 82, -48, -71, -124, 68, 49, -6, -60, -59, -90, 81, -88, 55, -26, 43, 56, 65, -88, -94, 2, 73, -9, 60, -57, 117, -5, 64, 48, 62, -76, -51, 103, -115, -38, -79, -76, 97, -89, 23, 68, 4, 49, -81, 0, 0, 4, 0, 0, 0, 1, 52, 0, 5, 0, 32, -60, -101, -91, -29, 83, -9, 0, 6, 0, 0, 0, 0, 1, 0, -113, 121, 53, -39, -71, -86, -23, -65, -85, -19, -120, 122, -49, 73, 81, -74, -13, 46, -59, -98, 59, -81, 55, 24, -24, -22, -60, -106, 31, 62, -3, 54, 6, -25, 67, 81, -87, -60, 24, 51, 57, -72, 9, -25, -62, -82, 28, 83, -101, -89, 71, 91, -123, -48, 17, -83, -72, -76, 121, -121, 117, 73, -124, 105, 92, -84, 14, -113, 20, -77, 54, 8, 40, -94, 47, -6, 39, 17, 10, 61, 98, -87, -109, 69, 52, 9, -96, -2, 105, 108, 70, 88, -8, 75, -35, 32, -127, -100, 55, 9, -96, 16, 87, -79, -107, -83, -51, 0, 35, 61, -70, 84, -124, -74, 41, 31, -99, 100, -114, -8, -125, 68, -122, 119, -105, -100, -20, 4, -76, 52, -90, -84, 46, 117, -23, -104, 93, -30, 61, -80, 41, 47, -63, 17, -116, -97, -6, -99, -127, -127, -25, 51, -115, -73, -110, -73, 48, -41, -71, -29, 73, 89, 47, 104, 9, -104, 114, 21, 57, 21, -22, 61, 107, -117, 70, 83, -58, 51, 69, -113, -128, 59, 50, -92, -62, -32, -14, 114, -112, 37, 110, 78, 63, -118, 59, 8, 56, -95, -60, 80, -28, -31, -116, 26, 41, -93, 125, -33, 94, -95, 67, -34, 75, 102, -1, 4, -112, 62, -43, -49, 22, 35, -31, 88, -44, -121, -58, 8, -23, 127, 33, 28, -40, 29, -54, 35, -53, 110, 56, 7, 101, -8, 34, -29, 66, -66, 72, 76, 5, 118, 57, 57, 96, 28, -42, 103, 0, 0, 0, 28, -70, -10, -106, -90, -123, 120, -9, -33, -34, -25, -6, 103, -55, 119, -57, -123, -17, 50, -78, 51, -70, -27, -128, -64, -68, -43, 105, 93, 0, 0, 1, 0, 22, -90, 92, 88, 32, 72, 80, 112, 78, 117, 2, -93, -105, 87, 4, 13, 52, -38, 58, 52, 120, -63, 84, -44, -28, -91, -64, 45, 36, 46, -32, 79, -106, -26, 30, 75, -48, -112, 74, -67, -84, -113, 55, -18, -79, -32, -97, 49, -126, -46, 60, -112, 67, -53, 100, 47, -120, 0, 65, 96, -19, -7, -54, 9, -77, 32, 118, -89, -100, 50, -90, 39, -14, 71, 62, -111, -121, -101, -94, -60, -25, 68, -67, 32, -127, 84, 76, -75, 91, -128, 44, 54, -115, 31, -88, 62, -44, -119, -23, 78, 15, -96, 104, -114, 50, 66, -118, 92, 120, -60, 120, -58, -115, 5, 39, -73, 28, -102, 58, -69, 11, 11, -31, 44, 68, 104, -106, 57, -25, -45, -50, 116, -37, 16, 26, 101, -86, 43, -121, -10, 76, 104, 38, -37, 62, -57, 47, 75, 85, -103, -125, 75, -76, -19, -80, 47, 124, -112, -23, -92, -106, -45, -91, 93, 83, 91, -21, -4, 69, -44, -10, 25, -10, 63, 61, -19, -69, -121, 57, 37, -62, -14, 36, -32, 119, 49, 41, 109, -88, -121, -20, 30, 71, 72, -8, 126, -5, 95, -34, -73, 84, -124, 49, 107, 34, 50, -34, -27, 83, -35, -81, 2, 17, 43, 13, 31, 2, -38, 48, -105, 50, 36, -2, 39, -82, -38, -117, -99, 75, 41, 34, -39, -70, -117, -29, -98, -39, -31, 3, -90, 60, 82, -127, 11, -58, -120, -73, -30, -19, 67, 22, -31, -17, 23, -37, -34, 0, 0, 1, 0, 73, -74, -95, -21, 93, 51, 114, 110, 113, 4, -101, -82, 60, -128, -50, 41, 9, -74, 67, 52, 61, -60, -124, -112, 48, 78, 28, -44, -109, -54, 47, -108, 62, 34, 100, 45, -90, -84, -29, -68, 7, 85, -90, 3, 35, 16, -26, -121, -124, -98, -64, -113, -77, 72, 52, -68, 0, -63, -111, -39, 0, 51, -47, 40, -123, 3, 107, -63, -109, -126, -99, -19, 11, -69, -67, -36, 59, -26, -111, -56, -37, 8, -11, 11, 99, 127, 48, -117, -89, -120, 61, 105, 122, 76, -107, 68, -82, -48, 95, 82, -53, 67, -101, -25, 106, -16, -68, 63, 18, 32, -17, -43, -72, -27, -50, -93, -49, -40, 18, 44, -39, 8, -19, 121, 3, 3, 46, -62, -16, 17, 33, 96, 66, -109, -46, -58, 18, -95, -33, 4, -35, 105, 26, -18, -82, 64, 71, -23, 53, -112, 82, 120, 45, -14, -69, -9, 94, 48, 109, -1, 43, -93, -35, 33, 62, -67, -92, 14, 72, -37, -109, 37, 57, -69, -15, 77, -64, -83, 39, 20, -127, 115, 87, -26, -36, 98, 44, -42, 62, 84, -8, -71, -97, 16, -126, -124, -88, -22, -55, 10, -102, -46, 80, 95, -24, 108, -69, 0, -5, 104, -29, -127, -55, -31, 9, -105, -12, -86, -86, 13, 110, -18, -76, 45, 33, -126, 84, 75, -51, 49, -55, 62, 108, 66, -82, -53, 77, -73, 81, 99, 16, 125, 65, 119, 91, -48, 6, -107, 54, 63, 37, -55, -62, -53, 88, 74, 0, 7, 0, 0, 0, 28, -108, -114, 107, -42, 89, 46, -77, -109, 12, 46, -22, 106, -100, 112, -64, 27, -128, -96, 61, 68, 105, -108, -96, 89, -79, 76, 21, -10, 0, 0, 0, 28, -93, -84, -79, -15, -125, -122, -58, 58, 6, -127, -128, 124, 95, 20, -20, 44, -54, 123, -2, -119, 1, 75, 72, -91, -71, 25, -127, -5, 16, -37, 39, -42, 109, -70, -96, -61, 2, -121, 108, -41, 53, -74, 32, 76, 46, 5, -109, 118, -124, 41, -119, -88, -27, 110, 48, -34, -79, -23, 2, -6, -74, 66, 57, 64, 85, -126, -37, -84, 125, -121, 81, -11, -32, -77, 94, -96, -112, -95, 67, 34, 6, 34, -104, -63, 0, 34, -95, 43, -6, -37, 117, 73, 29, 28, 111, -19, 77, 87, 26, 8, -86, -117, 86, -16, 9, -38, 16, 67, -12, -74, -10, 13, -39, 120, 22, 4, 119, -6, 69, -116, -13, -101, -58, -66, 55, 113, -8, 50, 107, 110, -60, -6, 37, 81, -62, 86, -23, -67, 29, -15, 17, 0}));
//        System.err.println("Payload: " + Arrays.toString(new OtrOutputStream().write(payload).toByteArray()));
//        final Point x = X;
        final Point x = new OtrInputStream(new byte[] {-76, 122, 45, -119, -10, -121, -38, -121, 77, -80, 110, 89, 95, -63, -33, 69, 87, -83, 92, 33, 54, 75, -23, -77, -102, 17, -86, -92, -112, -14, 7, -32, 20, -22, -107, -31, 115, 97, -31, -69, -4, 4, -93, 67, -58, -81, 18, -14, -46, 86, -5, -75, 1, 2, 113, 38, 0})
                .readPoint();
//        System.err.println("X: " + Arrays.toString(x.encode()));
//        final BigInteger a = A;
        final BigInteger a = new OtrInputStream(new byte[] {0, 0, 1, -128, -52, 72, 100, 125, 123, 5, 91, -32, 100, -63, 37, 18, -67, -7, -118, 67, 76, -90, -70, -28, -110, -64, -67, -88, 121, -10, 96, 1, -17, -10, -121, 22, 19, -106, -60, 21, 83, -8, 86, 120, -14, -73, -75, -92, -100, 100, 89, -59, -114, -127, 97, -2, 97, -31, 127, -68, -107, -90, -110, 73, -38, -38, 2, -91, 55, -50, 70, 20, -90, 42, -96, -38, 44, 66, 116, -5, 56, -66, -1, -3, 107, 107, 10, -39, -35, 80, -101, 84, 68, -15, -111, -55, -120, 45, 83, -105, -98, 35, 40, -98, 27, 45, -1, 123, 65, 110, 35, 66, -84, 117, 25, 31, 28, -67, -45, 100, -44, 74, -54, 91, 107, -127, 27, -75, -59, 46, -22, 45, 33, -33, -35, 95, -86, 22, 10, 127, -52, 23, -85, -72, 71, -14, -4, -48, 68, -72, -45, -106, 54, 6, -121, -31, -59, -50, -102, 82, -63, 40, 116, -53, -38, 107, 44, -106, -57, -109, 66, 90, 115, 10, -61, 83, 74, 126, 80, 104, -58, -36, -57, 22, 13, -67, -22, 103, 9, -126, -1, -126, -28, -92, 55, -102, 17, -28, 8, -25, 92, 112, -92, 103, 83, 1, -122, 42, -64, 67, -25, -47, 77, -77, -77, -65, 53, -6, -88, 87, -72, 0, 122, -92, -128, 20, -40, -36, 84, -11, -5, -57, 96, 40, 99, 76, 85, -89, -17, 57, -54, 12, 69, 89, -42, -50, -31, 78, -85, -107, 30, -103, 7, 79, -25, -19, 99, -101, -56, -126, 122, -102, -107, 71, -40, 57, 24, 10, 42, -112, -115, 41, -120, 106, 98, -70, 31, 94, -118, 125, -72, -34, -8, -115, 117, 22, -83, -36, -8, -33, 120, -24, -23, -110, -112, 59, -42, -62, -53, -87, -108, -128, 126, 7, 3, 19, 83, 8, -70, 49, -89, 126, 87, 19, -65, -11, 46, 17, 102, -117, 43, 77, -85, -91, -40, 103, -6, -66, 101, -96, 38, -7, 98, 103, 97, -56, 66, -58, 114, 67, 114, -99, 14, -62, -117, 46, -128, 107, 77, 13, 49, 97, 119, 44, 57, -39, -101, 51, 37, 63, -103, 17, -18, -52, 113, 28, -40, 38, -60, -93, -110, -17, 5, 14, -69, -65, -87, -88, 120, 40, 57, -11, -60, 70, -41, -101, 113, 89})
                .readBigInt();
//        System.err.println("A: " + Arrays.toString(new OtrOutputStream().writeBigInt(a).toByteArray()));
//        final byte[] m = new byte[] {-90, 84, 16, 36, 45, -96, 111, -13, -53, -2, 87, -36, 34, 99, -76, -121, 126, -51, -12, -97, 34, -95, -110, -100, -126, 3, -118, -104, 80, -107, 8, -15, 92, 67, -65, 36, 53, 73, -63, -25, 15, 83, 11, 54, -77, -25, 68, -105, -46, 63, 118, -40, -87, -106, -121, -124, -55, -88, 3, 78, 36, 12, 121, -3, -52, 123, -118, 117, 26, -73, -74, -76, -16, 114, 37, 81, 117, -87, 0, 107, -59, 93, -90, 89, -74, -68, -33, 12, -111, -56, 17, -90, -87, 29, -20, -15, 14, -63, -52, 77, -124, -83, 28, -85, 124, 97, -18, -77, -111, 43, -44, 48, -119, 7, -127, -111, 49, 13, -37, 10, 4, -5, -92, -51, -1, 75, -42, 87, 73, -112, 2, 72, 119, 81, -29, -10, -118, -62, 20, -30, 32, -81, 114, 11, -80, 82, 110, 13, -79, -43};
//        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        final Sigma sigma = Sigma.readFrom(new OtrInputStream(new byte[] {-27, 1, -126, -72, -95, -38, 21, 42, 92, 16, 118, 56, 6, 8, 102, 91, -40, -89, 46, -100, 77, 78, -18, 17, -82, -124, 84, -42, -72, -68, 57, 39, 66, 96, -102, 100, -126, 68, -61, 25, 82, 119, 84, 101, 112, 113, 26, -19, 104, -16, -49, -86, -31, -43, 89, 13, 0, -112, 4, -113, 63, -63, -45, -6, -93, -93, -10, 72, -8, -60, 61, 98, -95, -97, -8, 18, 48, -71, -119, -84, 73, -121, 20, -13, -37, -43, 67, 64, -86, 63, 32, -122, 85, 121, -117, 53, -75, -71, -80, 16, 111, 16, -13, 16, 68, -84, 105, 13, -95, 50, 84, -57, 11, 0, 92, 7, -47, -28, -17, 50, 35, -64, -31, 68, -56, -69, 106, -122, 43, 18, -125, -29, 100, -18, -78, 48, -66, -31, -68, 118, 21, 120, -65, 86, -124, -100, 81, 9, -113, 118, 79, -128, -85, 83, 25, -85, -22, -128, -62, 91, -61, -126, -37, 118, 11, -60, 117, -45, 127, 20, 0, -42, -119, 12, -118, -16, -97, 101, -71, -26, -15, -82, -39, 32, -86, -9, 99, -78, 10, 119, -41, 90, 37, -125, -2, 78, -23, -105, 57, 106, 35, -114, 18, 120, -62, 37, -38, 92, 55, -59, -60, -119, -119, -116, -20, -80, 7, 77, 86, -77, -35, 93, 99, 11, 28, 83, 20, 0, -126, -43, -82, 37, 32, 102, 54, 99, 25, -1, -82, -111, -78, -57, 78, -126, -96, 63, -7, -26, -24, 73, -126, 2, -118, -42, -55, -42, 20, 51, 56, -6, 75, -37, -122, 100, -39, -2, -101, 115, 84, 44, 16, 72, 23, 7, 97, -34, 7, -92, -114, 77, 79, -60, -44, 49, 0, 68, 84, -22, 17, -27, 96, -5, 76, 16, -7, -19, -45, -60, -86, -56, 92, -122, 106, 54, 23, -120, 75, -11, -111, -21, 62, -6, -54, -100, 50, -41, 96, 58, -72, 55, 5, 75, -32, 0, 10, -19, -71, 31, 61, -104, 28, -51, -69, -126, -7, -104, 42, 101, -36, 105, 38, 0}));
//        System.err.println("Sigma: " + Arrays.toString(new OtrOutputStream().write(sigma).toByteArray()));
//        final Point firstECDHPublicKey = FIRST_ECDH_PUBLIC_KEY;
        final Point firstECDHPublicKey = new OtrInputStream(new byte[] {-16, 26, 63, 18, 47, 2, -63, 65, -109, -11, -81, 70, 87, -74, 23, -79, -21, 30, -123, -74, -56, 90, -19, -106, 68, 96, 65, 36, 49, 21, -24, -87, 95, -115, -22, -122, -107, 4, -64, 67, -2, 5, 75, 99, -30, -27, 76, -87, 85, 77, -46, 62, 110, -112, -41, -84, -128})
                .readPoint();
//        System.err.println("First ECDH: " + Arrays.toString(new OtrOutputStream().writePoint(FIRST_ECDH_PUBLIC_KEY).toByteArray()));
//        final BigInteger firstDHPublicKey = FIRST_DH_PUBLIC_KEY;
        final BigInteger firstDHPublicKey = new OtrInputStream(new byte[] {0, 0, 1, -128, -126, 19, -113, 108, 29, -37, 98, -118, -97, -115, -72, 69, 30, 67, 24, 0, 114, -120, 86, 61, -86, 74, -27, 94, -4, -54, 52, 69, -106, -53, 50, 118, -56, 99, -79, -38, 21, -65, -59, 40, -49, -24, 64, 2, 65, -53, 75, 97, 121, -88, -2, -9, -45, 5, -64, 33, -94, -29, 14, 19, 71, -86, -54, 100, 73, 61, 102, 55, -2, -89, 125, 100, 19, 50, 72, -28, -88, 72, -17, -45, -19, -1, 93, -27, 38, -47, -105, 17, -50, 63, -95, 53, -122, 54, -45, 35, -105, -50, -49, 11, -45, 70, -67, -107, -102, 28, 46, -16, -69, -63, -20, -73, -94, 122, -8, 83, -19, -76, -53, 86, 6, 43, -119, 87, 2, 19, -108, -126, -68, -55, 106, 76, 125, 123, -7, -97, 121, -113, -19, 34, -106, -19, -65, 44, 19, 77, -46, -31, 110, -57, 83, 89, 17, 34, -33, -53, -15, 3, 74, -104, -66, -74, -78, -22, 38, -86, -97, -93, -80, -62, 76, 119, -31, 22, 3, 57, 85, -55, 63, -12, -53, -127, -61, -96, -34, -99, -73, 5, -51, -121, -3, 76, 81, 45, -66, 50, 94, 66, 60, 89, -63, 48, -58, -53, -84, 7, -65, 14, 65, 16, -68, -107, -111, -68, 57, -79, 111, 106, -98, -115, -5, 101, 6, 38, -81, 74, 47, 91, -24, 108, -14, 22, 24, 94, -122, -34, -68, 103, -119, 100, 29, -17, 80, -102, -85, 124, 3, 45, -87, 91, -56, 70, -110, -107, -7, 50, 97, -93, -123, -104, -38, 30, 70, 86, 123, 108, 89, 55, -30, 43, 49, -95, -47, -94, 1, -109, -71, 16, 49, -64, -98, -34, 12, -26, 38, 95, -47, 50, -107, -67, -13, 82, -57, 69, 95, 85, 97, 22, 16, 78, -109, 41, -115, -18, -40, -2, 54, 39, 78, -121, 97, 16, -91, 95, 112, -65, 52, -75, -26, 78, -22, 78, 92, -52, -47, 50, -93, 18, -37, 99, -16, 90, 41, -16, 4, 69, 34, -111, 72, 39, 74, 70, 103, 96, 68, -42, 59, 48, 12, -22, 123, 51, 119, -7, -7, 0, 38, -122, 97, 81, 33, -91, -117, 78, -106, 72, 101, -122, -122, -55, 52, -1, 55, 105, 29, -85, -113, -95, 69, -21, -69, 123, 59, -58})
                .readBigInt();
//        System.err.println("First DH: " + Arrays.toString(new OtrOutputStream().writeBigInt(firstDHPublicKey).toByteArray()));
        final AuthRMessage message = new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, payload, x, a,
                sigma, firstECDHPublicKey, firstDHPublicKey);
//        System.err.println("Result: " + Arrays.toString(new OtrOutputStream().write(message).toByteArray()));
        final byte[] expected = new byte[] {0, 4, 54, 0, 0, 1, 0, -1, -1, -1, -1, 0, 0, 0, 7, 0, 1, 0, 0, 1, 0, 0, 2, 0, 16, -4, -1, 65, 16, 17, 125, 35, 111, -70, -94, -74, 59, -24, -56, -32, 62, -123, 30, -7, -99, -26, -72, -4, -77, 0, 58, -58, 51, -105, 95, -103, 122, 91, 7, -88, -127, 7, 10, -107, 68, 21, 96, -89, -126, 19, 41, -74, 35, -32, 54, 63, 79, 31, -90, 84, -121, 0, 0, 3, 0, 18, 21, -67, -71, -17, 53, 127, -42, -126, 27, -115, 54, -89, -51, 82, -48, -71, -124, 68, 49, -6, -60, -59, -90, 81, -88, 55, -26, 43, 56, 65, -88, -94, 2, 73, -9, 60, -57, 117, -5, 64, 48, 62, -76, -51, 103, -115, -38, -79, -76, 97, -89, 23, 68, 4, 49, -81, 0, 0, 4, 0, 0, 0, 1, 52, 0, 5, 0, 32, -60, -101, -91, -29, 83, -9, 0, 6, 0, 0, 0, 0, 1, 0, -113, 121, 53, -39, -71, -86, -23, -65, -85, -19, -120, 122, -49, 73, 81, -74, -13, 46, -59, -98, 59, -81, 55, 24, -24, -22, -60, -106, 31, 62, -3, 54, 6, -25, 67, 81, -87, -60, 24, 51, 57, -72, 9, -25, -62, -82, 28, 83, -101, -89, 71, 91, -123, -48, 17, -83, -72, -76, 121, -121, 117, 73, -124, 105, 92, -84, 14, -113, 20, -77, 54, 8, 40, -94, 47, -6, 39, 17, 10, 61, 98, -87, -109, 69, 52, 9, -96, -2, 105, 108, 70, 88, -8, 75, -35, 32, -127, -100, 55, 9, -96, 16, 87, -79, -107, -83, -51, 0, 35, 61, -70, 84, -124, -74, 41, 31, -99, 100, -114, -8, -125, 68, -122, 119, -105, -100, -20, 4, -76, 52, -90, -84, 46, 117, -23, -104, 93, -30, 61, -80, 41, 47, -63, 17, -116, -97, -6, -99, -127, -127, -25, 51, -115, -73, -110, -73, 48, -41, -71, -29, 73, 89, 47, 104, 9, -104, 114, 21, 57, 21, -22, 61, 107, -117, 70, 83, -58, 51, 69, -113, -128, 59, 50, -92, -62, -32, -14, 114, -112, 37, 110, 78, 63, -118, 59, 8, 56, -95, -60, 80, -28, -31, -116, 26, 41, -93, 125, -33, 94, -95, 67, -34, 75, 102, -1, 4, -112, 62, -43, -49, 22, 35, -31, 88, -44, -121, -58, 8, -23, 127, 33, 28, -40, 29, -54, 35, -53, 110, 56, 7, 101, -8, 34, -29, 66, -66, 72, 76, 5, 118, 57, 57, 96, 28, -42, 103, 0, 0, 0, 28, -70, -10, -106, -90, -123, 120, -9, -33, -34, -25, -6, 103, -55, 119, -57, -123, -17, 50, -78, 51, -70, -27, -128, -64, -68, -43, 105, 93, 0, 0, 1, 0, 22, -90, 92, 88, 32, 72, 80, 112, 78, 117, 2, -93, -105, 87, 4, 13, 52, -38, 58, 52, 120, -63, 84, -44, -28, -91, -64, 45, 36, 46, -32, 79, -106, -26, 30, 75, -48, -112, 74, -67, -84, -113, 55, -18, -79, -32, -97, 49, -126, -46, 60, -112, 67, -53, 100, 47, -120, 0, 65, 96, -19, -7, -54, 9, -77, 32, 118, -89, -100, 50, -90, 39, -14, 71, 62, -111, -121, -101, -94, -60, -25, 68, -67, 32, -127, 84, 76, -75, 91, -128, 44, 54, -115, 31, -88, 62, -44, -119, -23, 78, 15, -96, 104, -114, 50, 66, -118, 92, 120, -60, 120, -58, -115, 5, 39, -73, 28, -102, 58, -69, 11, 11, -31, 44, 68, 104, -106, 57, -25, -45, -50, 116, -37, 16, 26, 101, -86, 43, -121, -10, 76, 104, 38, -37, 62, -57, 47, 75, 85, -103, -125, 75, -76, -19, -80, 47, 124, -112, -23, -92, -106, -45, -91, 93, 83, 91, -21, -4, 69, -44, -10, 25, -10, 63, 61, -19, -69, -121, 57, 37, -62, -14, 36, -32, 119, 49, 41, 109, -88, -121, -20, 30, 71, 72, -8, 126, -5, 95, -34, -73, 84, -124, 49, 107, 34, 50, -34, -27, 83, -35, -81, 2, 17, 43, 13, 31, 2, -38, 48, -105, 50, 36, -2, 39, -82, -38, -117, -99, 75, 41, 34, -39, -70, -117, -29, -98, -39, -31, 3, -90, 60, 82, -127, 11, -58, -120, -73, -30, -19, 67, 22, -31, -17, 23, -37, -34, 0, 0, 1, 0, 73, -74, -95, -21, 93, 51, 114, 110, 113, 4, -101, -82, 60, -128, -50, 41, 9, -74, 67, 52, 61, -60, -124, -112, 48, 78, 28, -44, -109, -54, 47, -108, 62, 34, 100, 45, -90, -84, -29, -68, 7, 85, -90, 3, 35, 16, -26, -121, -124, -98, -64, -113, -77, 72, 52, -68, 0, -63, -111, -39, 0, 51, -47, 40, -123, 3, 107, -63, -109, -126, -99, -19, 11, -69, -67, -36, 59, -26, -111, -56, -37, 8, -11, 11, 99, 127, 48, -117, -89, -120, 61, 105, 122, 76, -107, 68, -82, -48, 95, 82, -53, 67, -101, -25, 106, -16, -68, 63, 18, 32, -17, -43, -72, -27, -50, -93, -49, -40, 18, 44, -39, 8, -19, 121, 3, 3, 46, -62, -16, 17, 33, 96, 66, -109, -46, -58, 18, -95, -33, 4, -35, 105, 26, -18, -82, 64, 71, -23, 53, -112, 82, 120, 45, -14, -69, -9, 94, 48, 109, -1, 43, -93, -35, 33, 62, -67, -92, 14, 72, -37, -109, 37, 57, -69, -15, 77, -64, -83, 39, 20, -127, 115, 87, -26, -36, 98, 44, -42, 62, 84, -8, -71, -97, 16, -126, -124, -88, -22, -55, 10, -102, -46, 80, 95, -24, 108, -69, 0, -5, 104, -29, -127, -55, -31, 9, -105, -12, -86, -86, 13, 110, -18, -76, 45, 33, -126, 84, 75, -51, 49, -55, 62, 108, 66, -82, -53, 77, -73, 81, 99, 16, 125, 65, 119, 91, -48, 6, -107, 54, 63, 37, -55, -62, -53, 88, 74, 0, 7, 0, 0, 0, 28, -108, -114, 107, -42, 89, 46, -77, -109, 12, 46, -22, 106, -100, 112, -64, 27, -128, -96, 61, 68, 105, -108, -96, 89, -79, 76, 21, -10, 0, 0, 0, 28, -93, -84, -79, -15, -125, -122, -58, 58, 6, -127, -128, 124, 95, 20, -20, 44, -54, 123, -2, -119, 1, 75, 72, -91, -71, 25, -127, -5, 16, -37, 39, -42, 109, -70, -96, -61, 2, -121, 108, -41, 53, -74, 32, 76, 46, 5, -109, 118, -124, 41, -119, -88, -27, 110, 48, -34, -79, -23, 2, -6, -74, 66, 57, 64, 85, -126, -37, -84, 125, -121, 81, -11, -32, -77, 94, -96, -112, -95, 67, 34, 6, 34, -104, -63, 0, 34, -95, 43, -6, -37, 117, 73, 29, 28, 111, -19, 77, 87, 26, 8, -86, -117, 86, -16, 9, -38, 16, 67, -12, -74, -10, 13, -39, 120, 22, 4, 119, -6, 69, -116, -13, -101, -58, -66, 55, 113, -8, 50, 107, 110, -60, -6, 37, 81, -62, 86, -23, -67, 29, -15, 17, 0, -76, 122, 45, -119, -10, -121, -38, -121, 77, -80, 110, 89, 95, -63, -33, 69, 87, -83, 92, 33, 54, 75, -23, -77, -102, 17, -86, -92, -112, -14, 7, -32, 20, -22, -107, -31, 115, 97, -31, -69, -4, 4, -93, 67, -58, -81, 18, -14, -46, 86, -5, -75, 1, 2, 113, 38, 0, 0, 0, 1, -128, -52, 72, 100, 125, 123, 5, 91, -32, 100, -63, 37, 18, -67, -7, -118, 67, 76, -90, -70, -28, -110, -64, -67, -88, 121, -10, 96, 1, -17, -10, -121, 22, 19, -106, -60, 21, 83, -8, 86, 120, -14, -73, -75, -92, -100, 100, 89, -59, -114, -127, 97, -2, 97, -31, 127, -68, -107, -90, -110, 73, -38, -38, 2, -91, 55, -50, 70, 20, -90, 42, -96, -38, 44, 66, 116, -5, 56, -66, -1, -3, 107, 107, 10, -39, -35, 80, -101, 84, 68, -15, -111, -55, -120, 45, 83, -105, -98, 35, 40, -98, 27, 45, -1, 123, 65, 110, 35, 66, -84, 117, 25, 31, 28, -67, -45, 100, -44, 74, -54, 91, 107, -127, 27, -75, -59, 46, -22, 45, 33, -33, -35, 95, -86, 22, 10, 127, -52, 23, -85, -72, 71, -14, -4, -48, 68, -72, -45, -106, 54, 6, -121, -31, -59, -50, -102, 82, -63, 40, 116, -53, -38, 107, 44, -106, -57, -109, 66, 90, 115, 10, -61, 83, 74, 126, 80, 104, -58, -36, -57, 22, 13, -67, -22, 103, 9, -126, -1, -126, -28, -92, 55, -102, 17, -28, 8, -25, 92, 112, -92, 103, 83, 1, -122, 42, -64, 67, -25, -47, 77, -77, -77, -65, 53, -6, -88, 87, -72, 0, 122, -92, -128, 20, -40, -36, 84, -11, -5, -57, 96, 40, 99, 76, 85, -89, -17, 57, -54, 12, 69, 89, -42, -50, -31, 78, -85, -107, 30, -103, 7, 79, -25, -19, 99, -101, -56, -126, 122, -102, -107, 71, -40, 57, 24, 10, 42, -112, -115, 41, -120, 106, 98, -70, 31, 94, -118, 125, -72, -34, -8, -115, 117, 22, -83, -36, -8, -33, 120, -24, -23, -110, -112, 59, -42, -62, -53, -87, -108, -128, 126, 7, 3, 19, 83, 8, -70, 49, -89, 126, 87, 19, -65, -11, 46, 17, 102, -117, 43, 77, -85, -91, -40, 103, -6, -66, 101, -96, 38, -7, 98, 103, 97, -56, 66, -58, 114, 67, 114, -99, 14, -62, -117, 46, -128, 107, 77, 13, 49, 97, 119, 44, 57, -39, -101, 51, 37, 63, -103, 17, -18, -52, 113, 28, -40, 38, -60, -93, -110, -17, 5, 14, -69, -65, -87, -88, 120, 40, 57, -11, -60, 70, -41, -101, 113, 89, -27, 1, -126, -72, -95, -38, 21, 42, 92, 16, 118, 56, 6, 8, 102, 91, -40, -89, 46, -100, 77, 78, -18, 17, -82, -124, 84, -42, -72, -68, 57, 39, 66, 96, -102, 100, -126, 68, -61, 25, 82, 119, 84, 101, 112, 113, 26, -19, 104, -16, -49, -86, -31, -43, 89, 13, 0, -112, 4, -113, 63, -63, -45, -6, -93, -93, -10, 72, -8, -60, 61, 98, -95, -97, -8, 18, 48, -71, -119, -84, 73, -121, 20, -13, -37, -43, 67, 64, -86, 63, 32, -122, 85, 121, -117, 53, -75, -71, -80, 16, 111, 16, -13, 16, 68, -84, 105, 13, -95, 50, 84, -57, 11, 0, 92, 7, -47, -28, -17, 50, 35, -64, -31, 68, -56, -69, 106, -122, 43, 18, -125, -29, 100, -18, -78, 48, -66, -31, -68, 118, 21, 120, -65, 86, -124, -100, 81, 9, -113, 118, 79, -128, -85, 83, 25, -85, -22, -128, -62, 91, -61, -126, -37, 118, 11, -60, 117, -45, 127, 20, 0, -42, -119, 12, -118, -16, -97, 101, -71, -26, -15, -82, -39, 32, -86, -9, 99, -78, 10, 119, -41, 90, 37, -125, -2, 78, -23, -105, 57, 106, 35, -114, 18, 120, -62, 37, -38, 92, 55, -59, -60, -119, -119, -116, -20, -80, 7, 77, 86, -77, -35, 93, 99, 11, 28, 83, 20, 0, -126, -43, -82, 37, 32, 102, 54, 99, 25, -1, -82, -111, -78, -57, 78, -126, -96, 63, -7, -26, -24, 73, -126, 2, -118, -42, -55, -42, 20, 51, 56, -6, 75, -37, -122, 100, -39, -2, -101, 115, 84, 44, 16, 72, 23, 7, 97, -34, 7, -92, -114, 77, 79, -60, -44, 49, 0, 68, 84, -22, 17, -27, 96, -5, 76, 16, -7, -19, -45, -60, -86, -56, 92, -122, 106, 54, 23, -120, 75, -11, -111, -21, 62, -6, -54, -100, 50, -41, 96, 58, -72, 55, 5, 75, -32, 0, 10, -19, -71, 31, 61, -104, 28, -51, -69, -126, -7, -104, 42, 101, -36, 105, 38, 0, -16, 26, 63, 18, 47, 2, -63, 65, -109, -11, -81, 70, 87, -74, 23, -79, -21, 30, -123, -74, -56, 90, -19, -106, 68, 96, 65, 36, 49, 21, -24, -87, 95, -115, -22, -122, -107, 4, -64, 67, -2, 5, 75, 99, -30, -27, 76, -87, 85, 77, -46, 62, 110, -112, -41, -84, -128, 0, 0, 1, -128, -126, 19, -113, 108, 29, -37, 98, -118, -97, -115, -72, 69, 30, 67, 24, 0, 114, -120, 86, 61, -86, 74, -27, 94, -4, -54, 52, 69, -106, -53, 50, 118, -56, 99, -79, -38, 21, -65, -59, 40, -49, -24, 64, 2, 65, -53, 75, 97, 121, -88, -2, -9, -45, 5, -64, 33, -94, -29, 14, 19, 71, -86, -54, 100, 73, 61, 102, 55, -2, -89, 125, 100, 19, 50, 72, -28, -88, 72, -17, -45, -19, -1, 93, -27, 38, -47, -105, 17, -50, 63, -95, 53, -122, 54, -45, 35, -105, -50, -49, 11, -45, 70, -67, -107, -102, 28, 46, -16, -69, -63, -20, -73, -94, 122, -8, 83, -19, -76, -53, 86, 6, 43, -119, 87, 2, 19, -108, -126, -68, -55, 106, 76, 125, 123, -7, -97, 121, -113, -19, 34, -106, -19, -65, 44, 19, 77, -46, -31, 110, -57, 83, 89, 17, 34, -33, -53, -15, 3, 74, -104, -66, -74, -78, -22, 38, -86, -97, -93, -80, -62, 76, 119, -31, 22, 3, 57, 85, -55, 63, -12, -53, -127, -61, -96, -34, -99, -73, 5, -51, -121, -3, 76, 81, 45, -66, 50, 94, 66, 60, 89, -63, 48, -58, -53, -84, 7, -65, 14, 65, 16, -68, -107, -111, -68, 57, -79, 111, 106, -98, -115, -5, 101, 6, 38, -81, 74, 47, 91, -24, 108, -14, 22, 24, 94, -122, -34, -68, 103, -119, 100, 29, -17, 80, -102, -85, 124, 3, 45, -87, 91, -56, 70, -110, -107, -7, 50, 97, -93, -123, -104, -38, 30, 70, 86, 123, 108, 89, 55, -30, 43, 49, -95, -47, -94, 1, -109, -71, 16, 49, -64, -98, -34, 12, -26, 38, 95, -47, 50, -107, -67, -13, 82, -57, 69, 95, 85, 97, 22, 16, 78, -109, 41, -115, -18, -40, -2, 54, 39, 78, -121, 97, 16, -91, 95, 112, -65, 52, -75, -26, 78, -22, 78, 92, -52, -47, 50, -93, 18, -37, 99, -16, 90, 41, -16, 4, 69, 34, -111, 72, 39, 74, 70, 103, 96, 68, -42, 59, 48, 12, -22, 123, 51, 119, -7, -7, 0, 38, -122, 97, 81, 33, -91, -117, 78, -106, 72, 101, -122, -122, -55, 52, -1, 55, 105, 29, -85, -113, -95, 69, -21, -69, 123, 59, -58};
        assertArrayEquals(expected, new OtrOutputStream().write(message).toByteArray());
    }

    private static Sigma generateSigma(@Nonnull final EdDSAKeyPair keypair, @Nonnull final byte[] message) {
        final ECDHKeyPair pair1 = ECDHKeyPair.generate(RANDOM);
        final ECDHKeyPair pair2 = ECDHKeyPair.generate(RANDOM);
        return ringSign(RANDOM, keypair, keypair.getPublicKey(), pair1.getPublicKey(), pair2.getPublicKey(), message);
    }
}