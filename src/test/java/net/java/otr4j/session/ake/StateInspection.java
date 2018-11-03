/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.ake;

import java.lang.reflect.Field;
import net.java.otr4j.crypto.SharedSecret;

public final class StateInspection {
    
    private StateInspection() {
        // Utility class.
    }
    
    public static SharedSecret extractSharedSecret(final AuthState state) throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        if (state instanceof StateAwaitingSig) {
            final Field field = state.getClass().getDeclaredField("s");
            field.setAccessible(true);
            return (SharedSecret) field.get(state);
        }
        throw new UnsupportedOperationException("Unsupported state type.");
    }
}
