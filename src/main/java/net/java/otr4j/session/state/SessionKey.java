/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;

// TODO currently not doing any caching key/mac caching ... is this really an issue? (Seems harmless enough at first intuition.)
// TODO consider moving this class to crypto package(???)
final class SessionKey {

    private static final Logger LOGGER = Logger.getLogger(SessionKey.class.getName());

    private static final int CTR_TOPHALF_LENGTH = 8;

    private static final byte HIGH_RECEIVE_BYTE = (byte) 0x02;
    private static final byte LOW_RECEIVE_BYTE = (byte) 0x01;
    private static final byte HIGH_SEND_BYTE = LOW_RECEIVE_BYTE;
    private static final byte LOW_SEND_BYTE = HIGH_RECEIVE_BYTE;

    /**
     * Sending counter. OTR spec specifies "top half", i.e. first 8 bytes.
     *
     * NOTE that the all-zeroes sending counter value should never be used.
     */
    private final byte[] sendingCtr = new byte[8];
    /**
     * Receiving counter. OTR spec specifies "top half" i.e. first 8 bytes.
     */
    private final byte[] receivingCtr = new byte[8];

    private final int localKeyID;
    private final int remoteKeyID;
    private final KeyPair localKeyPair;
    private final DHPublicKey remotePublicKey;
    private final SharedSecret s;
    private final boolean high;

    private boolean used;

    SessionKey(final int localKeyID, @Nonnull final KeyPair localKeyPair,
            final int remoteKeyID, @Nonnull final DHPublicKey remotePublicKey)
            throws OtrCryptoException {
        this.localKeyID = localKeyID;
        this.remoteKeyID = remoteKeyID;
        this.localKeyPair = Objects.requireNonNull(localKeyPair);
        this.remotePublicKey = Objects.requireNonNull(remotePublicKey);
        this.s = OtrCryptoEngine.generateSecret(localKeyPair.getPrivate(),
                Objects.requireNonNull(remotePublicKey));
        // FIXME is use of 'abs()' in comparison of DH public keys valid? (Probably unnecessary addition ...)
        this.high = ((DHPublicKey)this.localKeyPair.getPublic()).getY().abs()
                .compareTo(remotePublicKey.getY().abs()) > 0;
        this.used = false;
    }

    int getLocalKeyID() {
        return localKeyID;
    }

    int getRemoteKeyID() {
        return remoteKeyID;
    }

    @Nonnull
    public KeyPair getLocalKeyPair() {
        return localKeyPair;
    }

    @Nonnull
    public DHPublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

    /**
     * Boolean indicating whether session key was used.
     *
     * @return Returns true if session key is used, or false otherwise.
     */
    boolean isUsed() {
        return used;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + this.localKeyID;
        hash = 89 * hash + this.remoteKeyID;
        return hash;
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
        final SessionKey other = (SessionKey) obj;
        if (this.localKeyID != other.localKeyID) {
            return false;
        }
        if (this.remoteKeyID != other.remoteKeyID) {
            return false;
        }
        if (!Objects.equals(this.localKeyPair, other.localKeyPair)) {
            return false;
        }
        return Objects.equals(this.remotePublicKey, other.remotePublicKey);
    }

    /**
     * Mark (receiving) session key as used.
     */
    void markUsed() {
        this.used = true;
    }

    /**
     * Compute MAC secret for corresponding sending AES key.
     *
     * @return Returns MAC secret.
     */
    @Nonnull
    byte[] sendingMAC() {
        LOGGER.finest("Calculated sending MAC key.");
        return OtrCryptoEngine.sha1Hash(sendingAESKey());
    }

    /**
     * Compute sending AES key for this session key.
     *
     * @return Returns sending AES key.
     */
    @Nonnull
    byte[] sendingAESKey() {
        final byte sendByte = high ? HIGH_SEND_BYTE : LOW_SEND_BYTE;
        final byte[] h1 = this.s.h1(sendByte);
        final byte[] key = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
        ByteBuffer.wrap(h1).get(key);
        LOGGER.finest("Calculated sending AES key.");
        return key;
    }

    /**
     * Compute MAC secret for corresponding receiving AES key.
     *
     * @return Returns MAC secret.
     */
    @Nonnull
    byte[] receivingMAC() {
        LOGGER.finest("Calculated receiving MAC key.");
        return OtrCryptoEngine.sha1Hash(receivingAESKey());
    }

    /**
     * Compute receiving AES key for this session key.
     *
     * @return Returns AES key.
     */
    @Nonnull
    byte[] receivingAESKey() {
        final byte receiveByte = high ? HIGH_RECEIVE_BYTE : LOW_RECEIVE_BYTE;
        final byte[] h1 = this.s.h1(receiveByte);
        final byte[] key = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
        ByteBuffer.wrap(h1).get(key);
        LOGGER.finest("Calculated receiving AES key.");
        return key;
    }

    /**
     * Acquire sending counter.The provided CTR value will be 16-byte in length.
     * The OTR spec defines that only the top-half must be used and incremented.
     *
     * NOTE that the sending ctr of all zeroes should never be used. The current
     * implementation prevents this by incrementing first and returning ctr
     * value after.
     *
     * @return Returns 16-byte CTR value of which the top half is sending
     * counter value and bottom half is zeroed.
     */
    @Nonnull
    byte[] acquireSendingCtr() {
        LOGGER.log(Level.FINEST,
                "Incrementing counter for (localkeyID, remoteKeyID) = ({0},{1})",
                new Object[]{this.localKeyID, remoteKeyID});
        for (int i = CTR_TOPHALF_LENGTH - 1; i >= 0; i--) {
            if (++sendingCtr[i] != 0) {
                break;
            }
        }
        return ByteBuffer.allocate(16).put(this.sendingCtr).array();
    }

    /**
     * Verify counter based on the previous counters that have been verified. We
     * require counter to be strictly larger then the previous counter.
     *
     * @param receivingCtr Counter to verify.
     * @return Returns extended counter that is extended to 16 bytes of which
     * the first 8 bytes is pristine provided receiving ctr value.
     * @throws SessionKey.ReceivingCounterValidationFailed In case of validation
     * failure.
     */
    @Nonnull
    byte[] verifyReceivingCtr(@Nonnull final byte[] receivingCtr) throws ReceivingCounterValidationFailed {
        if (receivingCtr.length != this.receivingCtr.length) {
            throw new ReceivingCounterValidationFailed("counter value lengths not identical");
        }
        for (int i = 0; i < this.receivingCtr.length; i++) {
            if (receivingCtr[i] > this.receivingCtr[i]) {
                // Receiving ctr value is indeed larger.
                // Persist new ctr value for future validations.
                System.arraycopy(receivingCtr, 0, this.receivingCtr, 0,
                        this.receivingCtr.length);
                // Lengthen ctr value for further use.
                return ByteBuffer.allocate(16).put(this.receivingCtr).array();
            }
            if (receivingCtr[i] < this.receivingCtr[i]) {
                throw new ReceivingCounterValidationFailed("lower counter value");
            }
        }
        // Note that by OTR spec we aren't allowed to accept all-zeroes spec.
        // Therefore, if all bytes are identical, fail receiving counter
        // validation.
        throw new ReceivingCounterValidationFailed("identical counter value");
    }

    /**
     * Acquire Extra Symmetric Key for this session key instance.
     *
     * @return Returns extra symmetric key bytes.
     */
    @Nonnull
    byte[] extraSymmetricKey() {
        return this.s.extraSymmetricKey();
    }

    /**
     * Exception indicating that receiving counter validation failed.
     */
    final class ReceivingCounterValidationFailed extends Exception {

        private static final long serialVersionUID = 2904530293964813552L;

        private ReceivingCounterValidationFailed(@Nonnull final String reason) {
            super("Receiving counter is illegal: " + reason);
        }
    }
}