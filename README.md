**NOTE**: *This version of otr4j is in active development for the adoption of the [OTRv4][OTRv4] specification that is being developed at this moment.*

# otr4j

## Progress

**Status**: *In active development. Current work should be considered at most prototype-quality and guaranteed insecure.

Development stages:

* Minimal working encryption (Interactive DAKE, message encryption/decryption, self-serving) a.k.a. "at least the bugs are symmetric :-)"
  * Assumes in-order messages, assumes no messages get lost, no non-interactive behavior, i.e. none of the fancy stuff.
* Socialist Millionaire's Protocol for OTRv4.
* Migrate OTRv4 DAKE state machine into OTRv4 Message state machine.
* Support for skipped messages, keeping track of skipped message keys.
* Full implementation for Interactive use-case
* ... (non-interactive use case, ...)

`TODO: development in progress ...`

Tool support:

* JSR-305 annotations for static analysis
* Introduce SpotBugs analysis at build-time.
  * spotbugs-annotations, to improve static analysis capabilities
* Introduce pmd analysis at build-time.

`TODO: development progress ...`

## Architectural considerations

* Correctness of off-the-record protocol implementation.
* Encapsulation of cryptographic material to prevent mistakes, excessive exposure.
* Logical structure that prevents or makes obvious programming errors.
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


# Features
. OTRv4 (draft) support
* OTRv2 and OTRv3 (OTRv1 support dropped per recommendation)
* Outbound fragmentation
* Extra symmetric key support
* 

`TODO: describe possibility to request new features regarding the completeness of implementation, compatibility with various platforms.`

# Limitations

* *otr4j supports message lengths up to 2^31.*  
Message sizes in OTR are defined as 4-byte *unsigned*. Due to Java's signed integer types, this implementation currently uses a signed integer. Therefore, the highest bit of the message length is interpreted as sign bit. Lengths over 2^31 are unsupported.
* *Message are not queued up.*
messages will be rejected while the connection is being established. Once the secure connection is established, message can again be sent.

# TODO list

`TODO: ...`

# Contributing / Help needed

* Peer-reviewing (for security, and for improvements in general)
* Integration into chat clients
* 

`TODO ...`

  [OTR]: https://otr.cypherpunks.ca/
  [jitsi]: https://jitsi.org/
  [OTRv2]: https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html
  [OTRv3]: https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html
  [OTRv4]: https://github.com/otrv4/otrv4
  [otr4j/otr4j]: https://github.com/otr4j/otr4j
