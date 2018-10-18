**NOTE**: *This version of otr4j is in active development for the adoption of the [OTRv4][OTRv4] specification that is being developed at this moment.*

The repository for otr4j OTRv4 development is [gitlab.com/cobratbq/otr4j][gitlab-repo] and is mirrored to [github.com/cobratbq/otr4j][github-repo].

# otr4j

## Progress

__Status__: _In active development_  
Current work should be considered __at most__ _prototype-quality and guaranteed insecure._ The development follows the _master_ branch of [OTRv4], but may lag behind in areas that currently lack development focus.

Development stages:

* ✔ Minimal working encryption (Interactive DAKE, message encryption/decryption, self-serving) a.k.a. "at least the bugs are symmetric :-)"
* ✔ Socialist Millionaire's Protocol for OTRv4.
* ⌛ Migrate Ed448-Goldilocks implementation to Bouncy Castle.
  * ✔ EdDSA long-term keypair
  * ECDH keypair
  * Verify if implementation is still concise and simple, given recent modifications to Point and Scalar internals.
* Migrate OTRv4 DAKE state machine into OTRv4 Message state machine.
* Support for skipped messages, keeping track of skipped message keys.
* Full implementation for "OTRv4 Interactive" use-case
* ...

## Functionality

* General Off-the-record operation:
  * ☑ Maintain mixed OTRv2, OTRv3, OTRv4 sessions.
  * ☑ Persistent instance tags
  * ☐ OTRv4 extension to OTR Error messages
  * ☐ 'Interactive DAKE' implemented as Message states i.s.o. AKE states.
  * ☐ OTRv4 operating modes (OTRv3-compatible, OTRv4-standalone, OTRv4-interactive-only).
* Cryptographic primitives:
  * Edd448-Goldilocks elliptic curve (temporary solution)
    * ☑ Temporary working solution
    * ☐ Migrate to BouncyCastle 1.60.
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
    * ☐ Store for skipped message keys (out-of-order messages)
  * Shared secrets management:
    * ☑ Ephemeral DH with 3072-bit parameters
    * ☑ Ephemeral ECDH based on Ed448-Goldilocks
    * ☑ Key rotation
  * ☑ Calculate _Encryption_, _MAC_ and _Extra Symmetric Key_ keys
  * ☑ Revealing used MAC keys
  * ☐ Periodic clean-up of "old" skipped message keys
  * ☐ Session expiration
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
* ...

## Operational

* Constant-time implementations:
  * ☑ MAC key comparison
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
  * ☐ Scalar arithmetic operations to directly operate on values in byte-array representation.
  * ☐ Point arithmetic operations to directly operate on values in byte-array representation.
* Robustness
  * ☑ otr4j does not handle Error-type exceptions.  
  _If critical situations occur, for instance `OutOfMemoryError`, then all bets are off._
  * ☑ otr4j protects itself against `RuntimeException`s caused by callbacks into the host application.
  _Any occurrence of a `RuntimeException` is considered a bug on the host application side, and is caught and logged by otr4j._

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
  * ☐ spotbugs-annotations to support managing clean-up of cryptographic key material
* ☐ Significant amount of unit tests to accompany the library. (Currently: 1000+)

## Architectural considerations

* Correctness of protocol implementation. (Obviously)
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

A short attempt was made to establish a independent, community-supported (friendly) fork of [otr4j][otr4j/otr4j].

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
  [gitlab-repo]: https://gitlab.com/cobratbq/otr4j
  [github-repo]: https://github.com/cobratbq/otr4j
