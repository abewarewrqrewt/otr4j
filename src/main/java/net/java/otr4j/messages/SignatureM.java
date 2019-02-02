/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.messages;

import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireNotEquals;

/**
 * The SignatureM payload.
 *
 * @author George Politis
 */
public final class SignatureM implements OtrEncodable {

    @Nonnull
    private final DHPublicKey localPubKey;

    @Nonnull
    private final DHPublicKey remotePubKey;

    @Nonnull
    private final DSAPublicKey localLongTermPubKey;

    private final int keyPairID;

    /**
     * Constructor.
     *
     * @param localPubKey            The local DH public key
     * @param remotePublicKey        The remote DH public key
     * @param localLongTermPublicKey The local long-term DSA public key
     * @param keyPairID              The key pair ID
     */
    public SignatureM(@Nonnull final DHPublicKey localPubKey, @Nonnull final DHPublicKey remotePublicKey,
            @Nonnull final DSAPublicKey localLongTermPublicKey, final int keyPairID) {
        this.localPubKey = requireNonNull(localPubKey);
        this.remotePubKey = requireNonNull(remotePublicKey);
        this.localLongTermPubKey = requireNonNull(localLongTermPublicKey);
        this.keyPairID = requireNotEquals(0, keyPairID);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + keyPairID;
        result = prime * result + localLongTermPubKey.hashCode();
        result = prime * result + localPubKey.hashCode();
        result = prime * result + remotePubKey.hashCode();
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
        if (!localLongTermPubKey.equals(other.localLongTermPubKey)) {
            return false;
        }
        if (!localPubKey.equals(other.localPubKey)) {
            return false;
        }
        return remotePubKey.equals(other.remotePubKey);
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writeBigInt(this.localPubKey.getY());
        out.writeBigInt(this.remotePubKey.getY());
        out.writePublicKey(this.localLongTermPubKey);
        out.writeInt(this.keyPairID);
    }
}
