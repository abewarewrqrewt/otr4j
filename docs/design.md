# Abstract

This document records the structure and design considerations of otr4j.

# Considerations

`TODO: refer to architectural considerations and clarify how we satisfy the various constraints.`

# Structure

The layered structure present in otr4j.

```
+-------------------+
|   <<session>>     |
|      state        |
| ake | smp | smpv4 |
|       api         |
|-------------------|
|     messages      |
|-------------------|
|      io           |
|-------------------|
|       api         |
|-------------------|
| util | crypto     |
+-------------------+
```

Dependencies must only go downwards.

# Packages

The purpose of the various packages are documented in the `package-info.java` files inside the package.

## net.java.otr4j.util

Utilities for types other than the otr4j types, such as plain Java types.

Utilities for otr4j types should be placed in the same package with the type itself.

## net.java.otr4j.crypto

Package that isolates the cryptography logic from the rest of the implementation. Any cryptography or security implementation types must be isolated in this package such that we do not expose it arbitrarily throughout the library.

An exception is made for interfaces. These may be used in other packages.

## net.java.otr4j.api

The otr4j domain types.

## net.java.otr4j.io

Basic input/output logic necessary for otr4j. Mainly encoding and decoding of types as specified by OTR.

## net.java.otr4j.messages

Composite types that represent messages either full or parts.

## net.java.otr4j.session

The root of the otr4j logic. The logic implements the API. Subpackages are there to separate various state machines.

- _api_: the _internal_ API for the state machines
- _state_: the session state machine
- _ake_: the OTRv3 AKE state machine
- _smp_: the OTRv3 Socialist Millionaire's Protocol state machine
- _smpv4_: the OTRv4 elliptic curve-based Socialist Millionaire's Protocol state machine

