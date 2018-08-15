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
// FIXME BC 1.60 provides Ed448-Goldilocks, consider migrating away and using that implementation.
// FIXME go through all cryptographically sensitive parts and place assertions where we expect non-zero/cryptorandom inputs. (For example, key material, checksums, etc.)
package net.java.otr4j.crypto;
