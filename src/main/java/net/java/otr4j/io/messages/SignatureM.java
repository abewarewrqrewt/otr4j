/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;

/**
 * 
 * @author George Politis
 */
public final class SignatureM implements OtrEncodable {

    private final DHPublicKey localPubKey;
    private final DHPublicKey remotePubKey;
    private final DSAPublicKey localLongTermPubKey;
    private final int keyPairID;

    public SignatureM(@Nonnull final DHPublicKey localPubKey, @Nonnull final DHPublicKey remotePublicKey,
            @Nonnull final DSAPublicKey localLongTermPublicKey, final int keyPairID) {
        this.localPubKey = requireNonNull(localPubKey);
        this.remotePubKey = requireNonNull(remotePublicKey);
        this.localLongTermPubKey = requireNonNull(localLongTermPublicKey);
        this.keyPairID = keyPairID;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + keyPairID;
        result = prime
                * result
                + ((localLongTermPubKey == null) ? 0 : localLongTermPubKey
                        .hashCode());
        result = prime * result
                + ((localPubKey == null) ? 0 : localPubKey.hashCode());
        result = prime * result
                + ((remotePubKey == null) ? 0 : remotePubKey.hashCode());
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
        final SignatureM other = (SignatureM) obj;
        if (keyPairID != other.keyPairID) {
            return false;
        }
        if (localLongTermPubKey == null) {
            if (other.localLongTermPubKey != null) {
                return false;
            }
        } else if (!localLongTermPubKey.equals(other.localLongTermPubKey)) {
            return false;
        }
        if (localPubKey == null) {
            if (other.localPubKey != null) {
                return false;
            }
        } else if (!localPubKey.equals(other.localPubKey)) {
            return false;
        }
        if (remotePubKey == null) {
            if (other.remotePubKey != null) {
                return false;
            }
        } else if (!remotePubKey.equals(other.remotePubKey)) {
            return false;
        }
        return true;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writeBigInt(this.localPubKey.getY());
        out.writeBigInt(this.remotePubKey.getY());
        out.writePublicKey(this.localLongTermPubKey);
        out.writeInt(this.keyPairID);
    }
}
