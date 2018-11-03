/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class SharedSecret4TestUtils {

    public static SharedSecret4 createSharedSecret4(final SecureRandom random, final DHKeyPair ourDHKeyPair,
                                       final ECDHKeyPair ourECDHKeyPair, final BigInteger theirDHPublicKey,
                                       final Point theirECDHPublicKey) {
        return new SharedSecret4(random, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }
}
