/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.messages;

import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * The payload representing the X value.
 *
 * @author George Politis
 */
public final class SignatureX implements OtrEncodable {

    private final DSAPublicKey longTermPublicKey;
    private final int dhKeyID;
    private final byte[] signature;

    /**
     * Constructor.
     *
     * @param ourLongTermPublicKey our long-term DSA public key
     * @param ourKeyID             our key ID
     * @param signature            the corresponding signature
     */
    public SignatureX(@Nonnull final DSAPublicKey ourLongTermPublicKey, final int ourKeyID,
            @Nonnull final byte[] signature) {
        this.longTermPublicKey = requireNonNull(ourLongTermPublicKey);
        this.dhKeyID = ourKeyID;
        assert !allZeroBytes(signature) : "Expected non-zero bytes for signature. This may indicate that a critical bug is present, or it may be a false warning.";
        this.signature = requireNonNull(signature);
    }

    /**
     * Get the long-term DSA public key.
     *
     * @return the long-term DSA public key.
     */
    @Nonnull
    public DSAPublicKey getLongTermPublicKey() {
        return longTermPublicKey;
    }

    /**
     * Get DH key id.
     *
     * @return Returns the DH key ID.
     */
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

    // TODO consider if we really need 'equals', if so consider removing instance comparison
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

    /**
     * Verify expected signature with signature in SignatureX.
     *
     * @param expectedSignature the expected signature to verify against the SignatureX signature
     * @throws OtrCryptoException In case of failures of a cryptographic nature.
     */
    public void verify(@Nonnull final byte[] expectedSignature) throws OtrCryptoException {
        DSAKeyPair.verifySignature(expectedSignature, this.longTermPublicKey, this.signature);
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writePublicKey(this.longTermPublicKey);
        out.writeInt(this.dhKeyID);
        out.writeDSASignature(this.signature);
    }
}
