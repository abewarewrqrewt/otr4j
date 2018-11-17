/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
/**
 * Package containing cryptographic support logic for otr4j.
 * <p>
 * Design constraints:
 * <ul>
 *     <li>Any class containing sensitive material, i.e. material that is expected to remain secret, must implement
 *     AutoCloseable as a way to clear the sensitive material. The AutoCloseable implementation is expected to securely
 *     destroy the sensitive material.</li>
 * </ul>
 *
 * Usage constraints:
 * <ul>
 *     <li>For any class that implements {@link java.lang.AutoCloseable}, any user needs to call
 *     {@link java.lang.AutoCloseable#close()} after use, such that the types get the opportunity to clean up sensitive
 *     material.</li>
 * </ul>
 */
package net.java.otr4j.crypto;
// TODO ensure that all AutoCloseable instances are closed after use. (i.e. thoroughly validate destroy-implementations)
// TODO investigate what we need to clean additionally for Point and BigInteger calculations where we use temporary instances during computation.
