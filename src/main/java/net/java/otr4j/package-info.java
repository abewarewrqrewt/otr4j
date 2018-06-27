/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO Upgrade to use of JUnit5 for unit tests. (May not be possible due to language level restrictions, Java 8+?)
// TODO consistent naming of constants used in OTRv4 parts of implementation. (Sometimes LENGTH is at the start of the constant, sometimes at the end.)
// TODO Verify that mitigation for OTRv2 MAC revalation bug is in place. (Refer to documentation about revealing MAC keys.)
// TODO remove OTRv2 support to comply with OTRv4 spec.
// TODO Verify that all files have the correct license header above the files.
// FUTURE could we create some kind of basic client such that we can perform cross-implementation testing and fuzzing?
// FUTURE does it make sense to have some kind of plug-in system for OTR extensions?
// FUTURE consider if it makes sense to have some kind of SecurityManager rule/policy that prevents code from inspecting any otr4j instances. (This can also be tackled by using otr4j as module, as you have to explicitly allow "opening up" to reflection.)
// FUTURE what's the status on reproducible builds of Java programs?
// FUTURE investigate usefulness of Java 9 module, maybe just as an experiment ...
// FUTURE consider implementing OTRDATA (https://dev.guardianproject.info/projects/gibberbot/wiki/OTRDATA_Specifications)
// FUTURE do something fuzzing-like to thoroughly test receiving user messages with various characters. Especially normal user messages that are picked up as OTR-encoded but then crash/fail processing because it's only a partially-valid OTR encoded message.
// TODO General questions on way-of-working for OTRv4:
//  * Should we allow OTRv3 if no transitional signature is available?
//  * Should anything be derived from the definite order of the long-term public keys in the client profile? (Not sure that makes sense if key pairs exist on disconnected clients.)
//  * After having successfully finished DAKE, should we forget about previously used QueryTag or remember it? Let's say that we initiate a OTRv4 session immediately (send Identity message), should we then reuse previous query tag, or start blank?
/**
 * otr4j.
 */
package net.java.otr4j;
