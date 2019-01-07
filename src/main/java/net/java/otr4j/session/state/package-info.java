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
// FIXME review state machine (allowed) transitions now that DAKE is in.
// FIXME spec says "Picks a compatible version of OTR listed on Alice's profile, and follows the specification for this version." --> review if this changes anything for the current control logic. (This seems to be for the future only, as we shouldn't pick OTRv3 if a ClientProfile is sent -- spec says version 4 must be present in profile.)