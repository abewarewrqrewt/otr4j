/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO verify that logging with parameters ('{}') works correctly.
// TODO migrate to using SpotBugs annotations, instead of dormant JSR-305. (Are these supported in IntelliJ?)
// TODO use @CleanupObligation to verify correct clean-up of cryptographically sensitive material.
// TODO Review rule exclusions for maven-compiler-plugin, SpotBugs, pmd, ...
// TODO Use maven-site-plugin (or similar) to generate a full report on the status of otr4j project.
// TODO Investigate use of SpotBugs and its annotation to manage "resources" and correct closing.
// TODO Upgrade to use of JUnit5 for unit tests. (May not be possible due to language level restrictions, Java 8+?)
// TODO consistent naming of constants used in OTRv4 parts of implementation. (Sometimes LENGTH is at the start of the constant, sometimes at the end.)
// TODO Verify that mitigation for OTRv2 MAC revalation bug is in place. (Refer to documentation about revealing MAC keys.)
// TODO remove OTRv2 support to comply with OTRv4 spec.
// TODO consider the effectiveness of clearing data as JVM might optimize the activity away due to data not being used afterwards.
// NOTE OTRv3 does not document that SMP TLVs should have IGNORE_UNREADABLE flag set. So for now, we're not setting the flag for SMP TLVs.
// FUTURE could we create some kind of basic client such that we can perform cross-implementation testing and fuzzing?
// FUTURE does it make sense to have some kind of plug-in system for OTR extensions?
// FUTURE consider if it makes sense to have some kind of SecurityManager rule/policy that prevents code from inspecting any otr4j instances. (This can also be tackled by using otr4j as module, as you have to explicitly allow "opening up" to reflection.)
// FUTURE what's the status on reproducible builds of Java programs?
// FUTURE investigate usefulness of Java 9 module, maybe just as an experiment ...
// FUTURE consider implementing OTRDATA (https://dev.guardianproject.info/projects/gibberbot/wiki/OTRDATA_Specifications)
// FUTURE do something fuzzing-like to thoroughly test receiving user messages with various characters. Especially normal user messages that are picked up as OTR-encoded but then crash/fail processing because it's only a partially-valid OTR encoded message.
// FIXME verify that description of process in https://github.com/otrv4/otrv4/blob/master/otrv4.md#receiving-an-identity-message - state=WAITING_AUTH_I is still accurate. Seems to talk about maintaining original message which cannot be because we deleted secure keys for our_ecdh_first and our_dh_first.
// TODO General questions on way-of-working for OTRv4:
//  * After having successfully finished DAKE, should we forget about previously used QueryTag or remember it? Let's say that we initiate a OTRv4 session immediately (send Identity message), should we then reuse previous query tag, or start blank?
//  * "Set their_ecdh as the 'Public ECDH key' from the message. Set their_dh as the 'Public DH Key' from the message, if it is not empty." are duplicate. Already included as part of Rotation instructions.
//  * OTRv4 ClientProfile verification does not clearly state what to do if DSA public key *without* transitional signature is found. (Drop DSA Public Key or reject profile completely.)
//  * Consider making an exception for the Identity message.
//    "Discard the message and optionally pass a warning to the participant if:
//    The recipient's own instance tag does not match the listed receiver instance tag."
//  * "Discard the (illegal) fragment if:" is missing criteria for index and total <= 65535.
//  * Nothing is said about case where sender and receiver tags are different in OTR-encoded message. (Should we consider a case where there is a difference illegal?)
//  * What to do if DH-Commit message is received as response to other client instance's query tag? (no receiver instance tag specified yet)
//  * Allow accepting fragments that have 0 receiver tag? (For benefit of DH-Commit and Identity messages.)
//  * Spec does not go into case "What to do if message from next/other ratchet arrives, but with index other than 0." (i.e. cannot decrypt, must reject.)
//    This is part of section "When you receive a Data Message:".
//  * Spec does not go into case "What to do if message arrives with ratchetId < i and messageId == 0.". You can't blindly start processing this message as your would screw up your rotation.
//    This is part of section "When you receive a Data Message:".
//  * Are or aren't active attacks part of the scope of OTRv4?
//    Section "Deletion of Stored Message Keys" describes measures against active malicious participants.
//  * Is there any documentation on how to behave if we are in an encrypted session, then get a new query message?
//    NO: sending query messages is not allowed. But then, what do we do if we still receive a query message?
//    - Expected behavior is to drop out of encrypted state and start new (D)AKE(?)
//    - We need to do something to protect user from sending intended-as-secure-message as plaintext accidentally due to losing a race (condition).
/**
 * otr4j.
 */
package net.java.otr4j;
