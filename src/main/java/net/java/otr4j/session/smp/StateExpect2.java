/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smp;

import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * SMP state in expectation of SMP message 2: Bob's message completing the DH
 * exchange.
 *
 * In this state we accept message 2 (TLV type 3).
 */
final class StateExpect2 extends AbstractSMPState {

    private final BigInteger secret;
    private final BigInteger x2;
    final BigInteger x3;

    StateExpect2(@Nonnull final SecureRandom sr, @Nonnull final BigInteger secret, @Nonnull final BigInteger x2,
            @Nonnull final BigInteger x3) {
        super(sr);
        this.secret = secret;
        this.x2 = x2;
        this.x3 = x3;
    }

    @Override
    @Nonnull
    SMPStatus status() {
        return SMPStatus.INPROGRESS;
    }

    @Override
    @Nonnull
    byte[] smpMessage2(@Nonnull final SM astate, @Nonnull final byte[] input) throws SMException {
        /* Read from input to find the mpis */

        final BigInteger[] msg2 = SM.deserialize(input);

        /* Verify parameters and let checks throw exceptions in case of failure.*/
        checkGroupElem(msg2[0]);
        checkGroupElem(msg2[3]);
        checkGroupElem(msg2[6]);
        checkGroupElem(msg2[7]);
        checkExpon(msg2[2]);
        checkExpon(msg2[5]);
        checkExpon(msg2[9]);
        checkExpon(msg2[10]);

        final BigInteger[] msg3 = new BigInteger[8];

        /* Store Bob's g3a value for later in the protocol */
        final BigInteger g3o = msg2[3];

        /* Verify Bob's knowledge of discreet log proofs */
        checkKnowLog(msg2[1], msg2[2], msg2[0], 3);
        checkKnowLog(msg2[4], msg2[5], msg2[3], 4);

        /* Combine the two halves from Bob and Alice and determine g2 and g3 */
        final BigInteger g2 = msg2[0].modPow(x2, DHKeyPairOTR3.MODULUS);
        final BigInteger g3 = msg2[3].modPow(x3, DHKeyPairOTR3.MODULUS);

        /* Verify Bob's coordinate equality proof */
        checkEqualCoords(msg2[8], msg2[9], msg2[10], msg2[6], msg2[7], g2, g3, 5);

        /* Calculate P and Q values for Alice */
        final BigInteger r = randomExponent();

        final BigInteger p = g3.modPow(r, DHKeyPairOTR3.MODULUS);
        msg3[0] = p;
        final BigInteger qa1 = G1.modPow(r, DHKeyPairOTR3.MODULUS);
        final BigInteger qa2 = g2.modPow(secret, DHKeyPairOTR3.MODULUS);
        final BigInteger q = qa1.multiply(qa2).mod(DHKeyPairOTR3.MODULUS);
        msg3[1] = q;

        BigInteger[] res = proofEqualCoords(g2, g3, secret, r, 6);
        msg3[2] = res[0];
        msg3[3] = res[1];
        msg3[4] = res[2];


        /* Calculate Ra and proof */
        BigInteger inv = msg2[6].modInverse(DHKeyPairOTR3.MODULUS);
        final BigInteger pab = p.multiply(inv).mod(DHKeyPairOTR3.MODULUS);
        inv = msg2[7].modInverse(DHKeyPairOTR3.MODULUS);
        final BigInteger qab = q.multiply(inv).mod(DHKeyPairOTR3.MODULUS);
        msg3[5] = qab.modPow(x3, DHKeyPairOTR3.MODULUS);
        res = proofEqualLogs(qab, x3, 7);
        msg3[6] = res[0];
        msg3[7] = res[1];

        final byte[] output = SM.serialize(msg3);

        astate.setState(new StateExpect4(this, g3o, pab, qab));

        return output;
    }
}
