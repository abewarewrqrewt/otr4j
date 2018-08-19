/**
 * Socialist Millionaire's Protocol for OTR version 4.
 */
package net.java.otr4j.session.smpv4;
// TODO Support querying the user whether to abort in-progress SMP before initiating new SMP.
// FIXME what to do if verification fails, status CHEATED still relevant? Send Abort message?
// TODO how important is it to clear the intermediate byte-arrays for SMP calculations?