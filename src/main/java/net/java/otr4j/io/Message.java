/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

/**
 * Interface representing any message recognized by Off-the-record.
 *
 * Messages are either a plain text or query message, in case of a plain message. Or an error message, in case of an
 * OTR error message to signal for an error. Or an OTR-encoded message, which can be any variety of messages. Or a
 * 'Fragment' in case of a fragmented OTR-encoded message.
 */
public interface Message {
}
