/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.crypto;

import java.security.SecureRandom;

import static net.java.otr4j.util.SecureRandoms.randomBytes;

public class SharedSecretTestUtil {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SharedSecretTestUtil() {
        // No need to instantiate utility class.
    }

    public static SharedSecret createTestSecret() {
        return new SharedSecret(randomBytes(RANDOM, new byte[24]));
    }
}
