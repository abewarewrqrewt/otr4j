/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
/**
 * Package containing cryptographic support logic for otr4j.
 */
// TODO ensure that StateEncrypted4, MessageKeys, DoubleRatchet, SharedSecret4 are cleared after use.
// TODO investigate what we need to clean additionally for Point and BigInteger calculations where we use temporary instances during computation.
package net.java.otr4j.crypto;
