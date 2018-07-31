/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * 
 * @author George Politis
 */
public final class SignatureX implements OtrEncodable {

    private final DSAPublicKey longTermPublicKey;
    private final int dhKeyID;
    private final byte[] signature;

    public SignatureX(@Nonnull final DSAPublicKey ourLongTermPublicKey, final int ourKeyID,
            @Nonnull  final byte[] signature) {
        this.longTermPublicKey = requireNonNull(ourLongTermPublicKey);
        this.dhKeyID = ourKeyID;
        this.signature = requireNonNull(signature);
    }

    @Nonnull
    public DSAPublicKey getLongTermPublicKey() {
        return longTermPublicKey;
    }

    public int getDhKeyID() {
        return dhKeyID;
    }

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
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SignatureX other = (SignatureX) obj;
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
        return constantTimeEquals(signature, other.signature);
    }

    public void verify(@Nonnull final byte[] expectedSignature) throws OtrCryptoException {
        OtrCryptoEngine.verify(expectedSignature, this.longTermPublicKey, this.signature);
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writePublicKey(this.longTermPublicKey);
        out.writeInt(this.dhKeyID);
        out.writeSignature(this.signature, this.longTermPublicKey);
    }
}
