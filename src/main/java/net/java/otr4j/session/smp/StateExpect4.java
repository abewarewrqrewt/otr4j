package net.java.otr4j.session.smp;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.OtrInputStream;

import javax.annotation.Nonnull;
import java.math.BigInteger;

/**
 * SMP state in expectation of SMP message 4: Bob's final message in SMP
 * exchange.
 *
 * In this state we accept message 4 (TLV type 5).
 */
final class StateExpect4 extends AbstractSMPState {

    private final BigInteger x3;
    private final BigInteger g3o;
    private final BigInteger pab;
    private final BigInteger qab;

    StateExpect4(@Nonnull final StateExpect2 previous, @Nonnull final BigInteger g3o,
                 @Nonnull final BigInteger pab, @Nonnull final BigInteger qab) {
        super(previous.secureRandom());
        this.x3 = previous.x3;
        this.g3o = g3o;
        this.pab = pab;
        this.qab = qab;
    }

    @Override
    @Nonnull
    SMPStatus status() {
        return SMPStatus.INPROGRESS;
    }

    @Override
    void smpMessage4(@Nonnull final SM astate, @Nonnull final byte[] input) throws SMException {
        /* Read from input to find the mpis */
        final BigInteger[] msg4;
        try {
            msg4 = SM.unserialize(input);
        } catch (final OtrInputStream.UnsupportedLengthException e) {
            throw new SMException("Unsupported situation by otr4j.", e);
        }

        /* Verify parameters and let checks throw exceptions in case of failure.*/
        checkGroupElem(msg4[0]);
        checkExpon(msg4[2]);

        /* Verify Bob's log equality proof */
        checkEqualLogs(msg4[1], msg4[2], msg4[0], g3o, qab, 8);

        /* Calculate Rab and verify that secrets match */

        final BigInteger rab = msg4[0].modPow(x3, OtrCryptoEngine.MODULUS);
        final int comp = rab.compareTo(pab);

        final SMPStatus status = (comp == 0) ? SMPStatus.SUCCEEDED : SMPStatus.FAILED;
        astate.setState(new StateExpect1(this.secureRandom(), status));
    }
}
