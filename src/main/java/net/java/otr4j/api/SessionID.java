/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * Session ID. Session ID is used to identify a single session based on
 * {@code (local account, remote account, protocol)} triple.
 *
 * @author George Politis
 */
@Immutable
public final class SessionID {

    @Nonnull
    private final String localAccountID;

    @Nonnull
    private final String remoteUserID;

    @Nonnull
    private final String protocolName;

    /**
     * A unique ID for an OTR session between two accounts.
     *
     * @param localAccountID the local account used for this conversation
     * @param remoteUserID the remote user on the other side of the conversation
     * @param protocolName the messaging protocol used for the conversation
     */
    public SessionID(@Nonnull final String localAccountID, @Nonnull final String remoteUserID,
            @Nonnull final String protocolName) {
        this.localAccountID = requireNonNull(localAccountID);
        this.remoteUserID = requireNonNull(remoteUserID);
        this.protocolName = requireNonNull(protocolName);
    }

    /**
     * Get local account ID.
     *
     * @return the {@code String} representing the local account
     */
    @Nonnull
    public String getAccountID() {
        return localAccountID;
    }

    /**
     * Get remote user ID.
     *
     * @return the {@code String} representing the remote user
     */
    @Nonnull
    public String getUserID() {
        return remoteUserID;
    }

    /**
     * Get protocol name.
     *
     * @return Returns protocol name.
     */
    @Nonnull
    public String getProtocolName() {
        return protocolName;
    }

    @Override
    public String toString() {
        return localAccountID + '_' + protocolName + '_' + remoteUserID;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + localAccountID.hashCode();
        result = prime * result + protocolName.hashCode();
        result = prime * result + remoteUserID.hashCode();
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
        final SessionID other = (SessionID) obj;
        if (!localAccountID.equals(other.localAccountID)) {
            return false;
        }
        if (!protocolName.equals(other.protocolName)) {
            return false;
        }
        return remoteUserID.equals(other.remoteUserID);
    }
}
