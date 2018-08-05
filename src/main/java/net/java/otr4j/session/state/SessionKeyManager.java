/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Collections.synchronizedList;

/**
 * Session key manager.
 *
 * @author Danny van Heumen
 */
final class SessionKeyManager {

    private static final Logger LOGGER = Logger.getLogger(SessionKeyManager.class.getName());

    /**
     * Secure random instance.
     */
    private final SecureRandom secureRandom;

    /**
     * Session keys. 2x2 "array" of session keys.
     */
    private final EnumMap<Index, EnumMap<Index, SessionKey>> keys = new EnumMap<>(Index.class);

    /**
     * List of old MAC keys for this session. (Synchronized)
     */
    private final List<byte[]> oldMacKeys = synchronizedList(new ArrayList<byte[]>(0));

    SessionKeyManager(@Nonnull final SecureRandom secureRandom,
            @Nonnull final KeyPair localKeyPair,
            @Nonnull final DHPublicKey remotePublicKey) throws OtrCryptoException {
        this.secureRandom = Objects.requireNonNull(secureRandom);
        // Prepare current set of session keys.
        final EnumMap<Index, SessionKey> current = new EnumMap<>(Index.class);
        current.put(Index.CURRENT, new SessionKey(1, localKeyPair, 1, remotePublicKey));
        current.put(Index.NEXT, new SessionKey(1, localKeyPair, 1, remotePublicKey));
        this.keys.put(Index.CURRENT, current);
        // Prepare next set of session keys.
        final KeyPair nextLocalDH = OtrCryptoEngine.generateDHKeyPair(this.secureRandom);
        final EnumMap<Index, SessionKey> next = new EnumMap<>(Index.class);
        next.put(Index.CURRENT, new SessionKey(2, nextLocalDH, 1, remotePublicKey));
        next.put(Index.NEXT, new SessionKey(2, nextLocalDH, 1, remotePublicKey));
        this.keys.put(Index.NEXT, next);
    }

    /**
     * Get session keys based on local and remote key IDs.
     *
     * @param localKeyId Local key ID.
     * @param remoteKeyId Remote key ID.
     * @return Returns session keys corresponding to local and remote key ID.
     * @throws SessionKeyManager.SessionKeyUnavailableException In case no
     * session key exists with specified local and remote key ID.
     */
    @Nonnull
    SessionKey get(final int localKeyId, final int remoteKeyId) throws SessionKeyUnavailableException {
        LOGGER.log(Level.FINEST, "Searching for session keys with (localKeyID, remoteKeyID) = ({0},{1})",
                new Object[]{localKeyId, remoteKeyId});
        for (final EnumMap<Index, SessionKey> sessionKeys : this.keys.values()) {
            for (final SessionKey key : sessionKeys.values()) {
                if (key.getLocalKeyID() == localKeyId && key.getRemoteKeyID() == remoteKeyId) {
                    LOGGER.finest("Matching keys found.");
                    return key;
                }
            }
        }
        throw new SessionKeyUnavailableException();
    }

    /**
     * Get encryption session keys.
     *
     * @return Returns session keys for encryption purposes in current state.
     */
    @Nonnull
    SessionKey getEncryptionSessionKeys() {
        LOGGER.finest("Getting encryption keys");
        return this.keys.get(Index.CURRENT).get(Index.NEXT);
    }

    /**
     * Get most recent session keys.
     *
     * @return Returns most recent session keys.
     */
    @Nonnull
    SessionKey getMostRecentSessionKeys() {
        LOGGER.finest("Getting most recent keys.");
        return this.keys.get(Index.NEXT).get(Index.NEXT);
    }

    /**
     * Rotate the local keys by generating new NEXT keys.
     *
     * @throws OtrCryptoException Exception in case of invalid keys.
     */
    void rotateLocalKeys() throws OtrCryptoException {
        LOGGER.finest("Rotating local keys.");
        final SessionKey sess1 = this.keys.get(Index.CURRENT).get(Index.NEXT);
        if (sess1.isUsed()) {
            LOGGER.finest("Detected used receiving MAC key in sessionkeys (CURRENT, NEXT) while rotating local keys. Adding the old MAC keys to reveal it.");
            this.oldMacKeys.add(sess1.receivingMAC());
        }
        final SessionKey sess2 = this.keys.get(Index.CURRENT).get(Index.CURRENT);
        if (sess2.isUsed()) {
            LOGGER.finest("Detected used receiving MAC key in sessionkeys (CURRENT, CURRENT) while rotation local keys. Adding the old MAC keys to reveal it.");
            this.oldMacKeys.add(sess2.receivingMAC());
        }

        // Rotate existing keys
        final SessionKey sess3 = this.keys.get(Index.NEXT).get(Index.NEXT);
        this.keys.get(Index.CURRENT).put(Index.NEXT, new SessionKey(
                sess3.getLocalKeyID(), sess3.getLocalKeyPair(),
                sess1.getRemoteKeyID(), sess1.getRemotePublicKey()));
        final SessionKey sess4 = this.keys.get(Index.NEXT).get(Index.CURRENT);
        this.keys.get(Index.CURRENT).put(Index.CURRENT, new SessionKey(
                sess4.getLocalKeyID(), sess4.getLocalKeyPair(),
                sess2.getRemoteKeyID(), sess2.getRemotePublicKey()));

        // Clear old session keys.
        sess1.clear();
        sess2.clear();

        // Generate new key for NEXT slots
        final KeyPair newKeyPair = OtrCryptoEngine.generateDHKeyPair(secureRandom);
        this.keys.get(Index.NEXT).put(Index.NEXT, new SessionKey(
                sess3.getLocalKeyID() + 1, newKeyPair,
                sess3.getRemoteKeyID(), sess3.getRemotePublicKey()));
        this.keys.get(Index.NEXT).put(Index.CURRENT, new SessionKey(
                sess4.getLocalKeyID() + 1, newKeyPair,
                sess4.getRemoteKeyID(), sess4.getRemotePublicKey()));
    }

    /**
     * Rotate remote session keys.
     *
     * @param nextRemoteDH The new public key for remote.
     * @throws OtrCryptoException Exception in case of invalid session key
     * components.
     */
    void rotateRemoteKeys(@Nonnull final DHPublicKey nextRemoteDH) throws OtrCryptoException {
        LOGGER.finest("Rotating remote keys.");
        final SessionKey sess1 = this.keys.get(Index.NEXT).get(Index.CURRENT);
        if (sess1.isUsed()) {
            LOGGER.finest("Detected used receiving MAC key for sessionkeys (NEXT, CURRENT) while rotating remote keys. Adding the old MAC keys to reveal it.");
            this.oldMacKeys.add(sess1.receivingMAC());
        }
        final SessionKey sess2 = this.keys.get(Index.CURRENT).get(Index.CURRENT);
        if (sess2.isUsed()) {
            LOGGER.finest("Detected used receiving MAC key for sessionkeys (CURRENT, CURRENT) while rotating remote keys. Adding the old MAC keys to reveal it.");
            this.oldMacKeys.add(sess2.receivingMAC());
        }

        // Rotate existing keys.
        final SessionKey sess3 = this.keys.get(Index.NEXT).get(Index.NEXT);
        this.keys.get(Index.NEXT).put(Index.CURRENT, new SessionKey(
                sess1.getLocalKeyID(), sess1.getLocalKeyPair(),
                sess3.getRemoteKeyID(), sess3.getRemotePublicKey()));
        final SessionKey sess4 = this.keys.get(Index.CURRENT).get(Index.NEXT);
        this.keys.get(Index.CURRENT).put(Index.CURRENT, new SessionKey(
                sess2.getLocalKeyID(), sess2.getLocalKeyPair(),
                sess4.getRemoteKeyID(), sess4.getRemotePublicKey()));

        // Clear old session keys.
        sess1.clear();
        sess2.clear();

        // Place new key in NEXT slots
        this.keys.get(Index.NEXT).put(Index.NEXT, new SessionKey(
                sess3.getLocalKeyID(), sess3.getLocalKeyPair(),
                sess3.getRemoteKeyID() + 1, nextRemoteDH));
        this.keys.get(Index.CURRENT).put(Index.NEXT, new SessionKey(
                sess4.getLocalKeyID(), sess4.getLocalKeyPair(),
                sess4.getRemoteKeyID() + 1, nextRemoteDH));
    }

    /**
     * Collect old MAC keys that were already used.
     *
     * @return Returns old, used MAC keys.
     */
    @Nonnull
    byte[] collectOldMacKeys() {
        LOGGER.finest("Collecting old MAC keys to be revealed.");
        synchronized (this.oldMacKeys) {
            int len = 0;
            for (final byte[] k : this.oldMacKeys) {
                len += k.length;
            }
            final ByteBuffer buff = ByteBuffer.allocate(len);
            for (final byte[] k : this.oldMacKeys) {
                buff.put(k);
            }
            this.oldMacKeys.clear();
            return buff.array();
        }
    }

    /**
     * Acquire the extra symmetric key that is facilitated by OTRv3.
     *
     * @return Returns extra symmetric key.
     */
    @Nonnull
    byte[] extraSymmetricKey() {
        return this.getEncryptionSessionKeys().extraSymmetricKey();
    }

    /**
     * Index identifiers for session keys storage.
     */
    private enum Index {
        CURRENT, NEXT
    }

    /**
     * Exception indicating that session key could not be found.
     */
    static final class SessionKeyUnavailableException extends Exception {

        private static final long serialVersionUID = 7887960733134415672L;

        private SessionKeyUnavailableException() {
            super("SessionKey is not available.");
        }
    }
}
