/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
/**
 * Package containing the Messaging states defined by OTR.
 */
package net.java.otr4j.session.state;
// TODO verify which Messaging state transitions are supported, such as: transition from OTRv4-Encrypted to OTRv3-Encrypted, or OTRv3-Encrypted to OTRv4-Encrypted. (Transitioning to lower protocol version is acceptable?)
// TODO introduce message send-queue while encrypted session is not yet established.
// FIXME introduce state "AWAITING_DAKE_DATA_MESSAGE" for finalizing Interactive/Non-Interactive DAKE. (Recently added due to issues with fully initializing Double Ratchet.)
