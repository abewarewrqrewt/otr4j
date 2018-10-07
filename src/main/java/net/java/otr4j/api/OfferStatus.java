/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.api;

/**
 * The offer status.
 * <p>
 * The offer status is used to indicate whether the whitespace tag was sent as an offer to initiate an encrypted
 * session.
 *
 * @author alexander.ivanov
 */
public enum OfferStatus {
    /**
     * Idle indicates that no relevant actions was taken yet regarding an offer to establish OTR session.
     */
    IDLE,
    /**
     * Sent indicates the whitespace-tag offer signal was sent.
     */
    SENT,
    /**
     * Rejected indicates that an offer attempt was made, but reply was a plain text reply and hence the offer is
     * considered failed.
     */
    REJECTED,
    /**
     * Accepted indicates that the previously sent offer was accepted.
     */
    ACCEPTED
}
