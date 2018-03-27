/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO Verify that mitigation for OTRv2 MAC revalation bug is in place. (Refer to documentation about revealing MAC keys.)
// FUTURE could we create some kind of basic client such that we can perform cross-implementation testing and fuzzing?
// FUTURE does it make sense to have some kind of plug-in system for OTR extensions?
// FUTURE consider if it makes sense to have some kind of SecurityManager rule/policy that prevents code from inspecting any otr4j instances. (This can also be tackled by using otr4j as module, as you have to explicitly allow "opening up" to reflection.)
// FUTURE what's the status on reproducible builds of Java programs?
// FUTURE investigate usefulness of Java 9 module, maybe just as an experiment ...
// FUTURE consider implementing OTRDATA (https://dev.guardianproject.info/projects/gibberbot/wiki/OTRDATA_Specifications)
// FUTURE do something fuzzing-like to thoroughly test receiving user messages with various characters. Especially normal user messages that are picked up as OTR-encoded but then crash/fail processing because it's only a partially-valid OTR encoded message.
/**
 * otr4j.
 */
package net.java.otr4j;
