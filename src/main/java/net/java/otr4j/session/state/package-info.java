/**
 * Package containing the Messaging states defined by OTR.
 */
package net.java.otr4j.session.state;
// TODO verify which Messaging state transitions are supported, such as: transition from OTRv4-Encrypted to OTRv3-Encrypted, or OTRv3-Encrypted to OTRv4-Encrypted. (Transitioning to lower protocol version is acceptable?)
// FIXME Modify OTRv4 DAKE states to be part of Message state machine, instead of current AKE state machine.
// TODO consider if we want to keep exact list of MAC keys such that we can verify revelation protocol is working and correct for other party.
