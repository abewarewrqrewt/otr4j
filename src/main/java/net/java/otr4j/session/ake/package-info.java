/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
/**
 * Implementation of AKE following the state pattern.
 *
 * This implementation will throw unchecked exceptions in case support in the
 * JVM is lacking, such as for required hashing functions and ciphers.
 */
// TODO should all states except for Initial (AUTHSTATE_NONE) have some kind of inherent time-out such that we cannot infinitely "stay" on a single state? (e.g. AWAITING_DHKEY in case of DH-Commit w/o receiver tag)
// FIXME introduce state "AWAITING_DAKE_DATA_MESSAGE" for finalizing Interactive/Non-Interactive DAKE. (Recently added due to issues with fully initializing Double Ratchet.)
package net.java.otr4j.session.ake;
