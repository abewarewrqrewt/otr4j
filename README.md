**NOTE**: *This version of otr4j is in active development for the adoption of the [OTRv4][OTRv4] specification that is being developed at this moment.*

The repository for otr4j OTRv4 development is [github.com/otr4j/otr4j][otr4j/otr4j].

# otr4j

## Progress

__Status__: _In active development_  
Current work should be considered __at most__ _prototype-quality and guaranteed insecure._ The development follows the _master_ branch of [OTRv4], but may lag behind in areas that currently lack development focus.

Development stages:

* ✔ Minimal working encryption (Interactive DAKE, message encryption/decryption, self-serving) a.k.a. "at least the bugs are symmetric :-)"
* ✔ Socialist Millionaire's Protocol for OTRv4.
* ✔ Migrate OTRv4 DAKE state machine into OTRv4 Message state machine.
* ⌛ Migrate Ed448-Goldilocks implementation to Bouncy Castle.
  * ✔ EdDSA long-term keypair
  * ECDH keypair  
  _Requires additions to the BouncyCastle API, as certain necessary operations are not currently supplied._
  * Verify if implementation is still concise and simple, given recent modifications to Point and Scalar internals.
* Support for skipped messages, keeping track of skipped message keys.
* Full implementation of "OTRv3-compatible" + "OTRv4 Interactive" use-case (including all FIXMEs)
* ... (OTRv4 Non-interactive, ...)
* Clean up remaining TODOs
* Review the many logging statements and verify if log levels are reasonable.

## Functionality

* General Off-the-record operation:
  * ☑ Maintain mixed OTRv2, OTRv3, OTRv4 sessions.
  * ☑ Persistent instance tags
  * ☑ 'Interactive DAKE' implemented as Message states i.s.o. AKE states.
  * ☐ OTRv4 extension to OTR Error messages
  * ☐ OTRv4 operating modes (OTRv3-compatible, OTRv4-standalone, OTRv4-interactive-only).
  * ☐ Queueing of messages while not in `ENCRYPTED_MESSAGES` state.
* Cryptographic primitives:
  * Edd448-Goldilocks elliptic curve (temporary solution)
    * ☑ Temporary working solution
    * ⌛ Migrate to BouncyCastle 1.60.
  * 3072-bit Diffie-Hellman parameters
    * ☑ Temporary working solution
    * ☐ Verify if current solution is acceptable, otherwise migrate to JCA/BC
  * ☑ XSalsa20 symmetric cipher
  * ☑ SHAKE-256
  * ☑ Ring signatures
* Key Exchange:
  * ☑ Interactive DAKE
  * ☐ Non-interactive DAKE
* Key Management:
  * Double Ratchet:
    * ☑ Generate next message keys (in-order messages)
    * ☑ Generate future message keys (skip over missing messages)
    * ☐ Store and recall skipped message keys (out-of-order messages)
  * Shared secrets management:
    * ☑ Ephemeral DH with 3072-bit parameters
    * ☑ Ephemeral ECDH based on Ed448-Goldilocks
    * ☑ Key rotation
  * ☑ Calculate _Encryption_, _MAC_ and _Extra Symmetric Key_ keys
  * ☑ Revealing used MAC keys
  * ☐ Periodic clean-up of "old" skipped message keys
  * ☐ Session expiration (and revealing remaining MAC keys)
* Message encryption/decryption:
  * ☑ In-order messages
  * ☑ In-order messages with some messages missing
  * ☐ Out-of-order messages
* Fragmentation and re-assembly:
  * ☑ Fragmentation
  * ☑ Re-assembling fragmented messages
* Socialist Millionaire's Protocol:
  * ☑ OTRv2/OTRv3
  * ☑ OTRv4
* Client and PreKey Profiles:
  * ☑ Client Profile support
  * ☐ PreKey profile support
* Extra Symmetric Key support:
  * ☑ OTRv3
  * OTRv4
    * ☑ Base "Extra Symmetric Key" available for use.
    * ☐ Derived keys based on OTRv4 prescribed key derivation
* Misc
  * ☑ Set flag `IGNORE_UNREADABLE` also for OTRv3 DISCONNECT and all SMP messages.  
  _Although not explicitly document that this is necessary, it should not break any existing applications. This makes implementations of OTRv3 and OTRv4 more similar and promotes better behavior in general, being: the other party is not needlessly warned for (lost) messages that do not contain valuable content, i.e. they are part of the OTR process, but do not contain user content themselves._
  * ☐ Ability to define own, customized per network, `phi` (shared session state) implementer addition for the `t` value calculation.

## Operational

* Constant-time implementations:
  * ☑ MAC key comparison
  * ☑ Point and Scalar equality
  * ☐ Scalar value comparison
  * ☐ Ring signatures implemented fully constant-time.
* Cleaning up data:
  * ☑ Clearing byte-arrays containing sensitive material after use.
  * ☐ Clean up remaining message keys instances when transitioning away from encrypted message states.
  * ☐ Investigate effectiveness of clearing byte-arrays right before potential GC. (Maybe they are optimized away by JVM?)
* Verify OTR-protocol obligations of other party:
  * ☑ Verify that revealed MAC keys are present when expected. (I.e. is list of revealed MAC keys larger than 0 bytes?)
* In-memory representation of points and scalar values as byte-arrays:  
  _Note that we specifically refer to how the data is represented in memory. Operations require temporary conversion back and forth into an intermediate type._
  * ☑ Points kept as byte-arrays.
  * ☑ Scalar values kept as byte-arrays.
* Mathematical operations act on byte-array representations directly:  
  _See also [BearSSL big integer operations](https://www.bearssl.org/bigint.html)_
  * ☐ Scalar arithmetic operations
  * ☐ Point arithmetic operations
* Robustness
  * ☑ otr4j does not handle Error-type exceptions.  
  _If critical situations occur, for instance `OutOfMemoryError`, then all bets are off._
  * ☑ otr4j protects itself against `RuntimeException`s caused by callbacks into the host application.
  _Any occurrence of a `RuntimeException` is considered a bug on the host application side, and is caught and logged by otr4j._
* Stability
  * ☐ Profile library in execution.
  * ☐ Measure memory usage changes under long-term use/heavy load.
* OTRv3 - catching up:
  * ☐ In-memory representation for OTRv3.
  * ☐ Arithmetical operations on byte-arrays for OTRv2 and/or OTRv3 logic.

## Developmental

* ☑ Encapsulate cryptographic material such that design facilitates appropriate use and maintenance.
* ☑ States, such as Message states, isolated as to prevent mistakes in mixing up variables and state management for different states.
* ☑ Strategically placed assertions to discover mistakes such as uninitialized/cleared byte-arrays.
* Tool support:
  * ☑ JSR-305 annotations for static analysis
  * ☑ Introduce compiler warnings failure at build-time
  * ☑ Introduce pmd analysis at build-time.
  * ☑ Introduce SpotBugs analysis at build-time
  * ☑ Introduce checkstyle at build-time to guard formatting/style
  * ☑ Introduce checkstyle _ImportControl_ module to guard the design structure
  * ☐ Introduce [Animal sniffer](https://www.mojohaus.org/animal-sniffer/) build plug-in to verify that we do not break backwards-compatibility, once released.
  * ☐ spotbugs-annotations to support managing clean-up of cryptographic key material
  * ☐ Experiment with features of [Checker Framework](https://checkerframework.org).
* ☐ Significant amount of unit tests to accompany the library. (Currently: 1100+)
* ⌛ Issue: some tests fail on a rare occasion due to the `assert` checks that are embedded in the code. These tests should be updated to assume successful execution if input would trigger the assertion.

## Architectural considerations

* Correctness of protocol implementation.
* Encapsulation of cryptographic material to prevent mistakes, misuse, excessive exposure.
* Design/structure that prevents or makes obvious programming errors.
* Restricted implementation, only as much abstraction as needed. (Simplicity)

# Synopsis

otr4j is an implementation of the [OTR (Off The Record) protocol][OTR]
in Java. Its development started during the GSoC '09
where the goal was to add support for OTR in [jitsi]. It currently
supports [OTRv2] and [OTRv3]. Additionally, there is support for
fragmenting outgoing messages.

Support for OTRv1 is removed, as is recommended by the OTR team.

For a quick introduction on how to use the library have a look at the
[DummyClient](src/test/java/net/java/otr4j/test/dummyclient/DummyClient.java).

# Limitations

* _otr4j supports message lengths up to 2^31._  
Message sizes in OTR are defined as 4-byte _unsigned_. Due to Java's signed integer types, this implementation currently uses a signed integer. Therefore, the highest bit of the message length is interpreted as sign bit. Lengths over 2^31 are unsupported.
* _Message are not queued up._  
Messages will be rejected while the connection is being established. Once the secure connection is established, message can again be sent.

# Contributing / Help needed

* Peer-reviewing (for correctness, security and improvements in general)
* Integration into chat clients

  [OTR]: https://otr.cypherpunks.ca/
  [jitsi]: https://jitsi.org/
  [OTRv2]: https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html
  [OTRv3]: https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html
  [OTRv4]: https://github.com/otrv4/otrv4
  [otr4j/otr4j]: https://github.com/otr4j/otr4j
