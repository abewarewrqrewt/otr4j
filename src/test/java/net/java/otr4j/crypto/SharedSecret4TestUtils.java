package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;

import java.math.BigInteger;

public final class SharedSecret4TestUtils {

    public static SharedSecret4 create(final DHKeyPair ourDHKeyPair, final ECDHKeyPair ourECDHKeyPair,
                                       final BigInteger theirDHPublicKey, final Point theirECDHPublicKey) throws OtrCryptoException {
        return new SharedSecret4(ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }
}
