/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * 
 * @author George Politis
 */
public final class SignatureX {

    // Fields.
    public final DSAPublicKey longTermPublicKey;
    public final int dhKeyID;
    public final byte[] signature;

    // Ctor.
    public SignatureX(final DSAPublicKey ourLongTermPublicKey, final int ourKeyID,
            final byte[] signature) {
        this.longTermPublicKey = ourLongTermPublicKey;
        this.dhKeyID = ourKeyID;
        this.signature = signature;
    }

    // Methods.
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + dhKeyID;
        result = prime
                * result
                + ((longTermPublicKey == null) ? 0 : longTermPublicKey
                        .hashCode());
        result = prime * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        SignatureX other = (SignatureX) obj;
        if (dhKeyID != other.dhKeyID) {
            return false;
        }
        if (longTermPublicKey == null) {
            if (other.longTermPublicKey != null) {
                return false;
            }
        } else if (!longTermPublicKey.equals(other.longTermPublicKey)) {
            return false;
        }
        if (!constantTimeEquals(signature, other.signature)) {
            return false;
        }
        return true;
    }

}
