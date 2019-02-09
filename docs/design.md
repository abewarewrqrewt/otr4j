# Abstract

This document records the structure and design considerations of otr4j.

# Architectural guidelines

A limited number of architectural considerations have been chosen, ordered by priority.

1. __Correctness__  
The code must implement the OTR-protocol specification correctly.
1. __Security__  
Care for security-sensitive parts of the code. Consideration of side-channels, protect cryptographic material from
accidents, misuse and abuse. This order assumes that protocol correctness includes security properties, as is reasonable to expect.
1. __Design that prevents or makes obvious programming errors__  
Write the code in such a way that unexpected behavior becomes obvious.
1. __Simplicity__  
Introduce complexity only at those points where it is required. This includes both simplicity from the adopting user's point-of-view and the otr4j implementation's point-of-view.

`TODO: refer to architectural considerations and clarify how we satisfy the various constraints.`

# Design considerations

The design considerations that have been taken into account. These relate to the stated architectural guidelines.

## Correctness

`TODO: describe correctness`

- static analysis (nullability, checking of critical return values, typical bug patterns, ...)
- strictly separating states to ensure correct behavior:
  - handle race conditions in syntax: independent of whether the state transition "was detected in the logic" (is transparent to the logic).
  - avoids mixing up and messing up data manipulations due to sudden, "unexpected" state changes.

## Security

- Cryptographic implementations are isolated to the `crypto` package and subpackages. (Guarded by [import-control](https://checkstyle.org/config_imports.html#ImportControl).)
- Sensitive / secret cryptographic material is not exposed, i.e. internal state, managed by a class inside `crypto` package.
- Classes designed to support `java.lang.AutoCloseable` to clear sensitive material after use.
- Public API chosen such that mistakes are not possible: (in particular, classes should not need an extensive user manual)
  - `decrypt` --> authenticate then-if-authentication-succeeds decrypt, only succeeds if authentication and decryption both succeed.
  - `encrypt` --> generate the nonce then encrypt, then return both. Simple API.
  - `verify` --> throws checked exception such that you cannot forget to check the result.
  - `ClientProfilePayload`: `ClientProfile`, i.e. individual field values of the client profile itself, are only accessible after successful validation.
- Take into account certain side-channels, for as far as possible in Java given the JVM.
  - Constant-time comparison of sensitive data.
- Strict state separation ensures that cryptographic code only needs to be implemented in encrypted states. (No possibility for state confusion)

## Design that prevents or makes obvious programming errors

- Fail-fast (bugs become apparent due to unchecked exceptions)
- Significant error handling part of syntax (checked exceptions)
- Annotations to extend static analysis.
- Deliberately work with most-restricted scopes.
- State machines, to make state transitions strict, inescapable events. States expressed in syntax.
- Alerts in case of high-unlikely situations. (Assertions)
- Misses/oversights in case analysis and case handling.
- Warn in case of bad behavior on the host application-side.
- Do not try to mitigate everything: (system) errors are not handled.

## Simplicity

- As few "moving parts" as possible. Extensive use of `final` fields. Avoid unnecessary reuse.
- Only a single "top-level" checked exception `OtrException`, such that you're not forced into unnecessarily complicated exception handling.
- No need to take into account unchecked exceptions. (If they occur: either incorrect use of library or bug in library itself. In both cases, it indicates something that needs to be fixed, not something that needs to be handled.)
- Classes should not need an extensive user manual, usage should be obvious.
- Documentation for anything that is part of the public API.
- Use public fields for classes that are only used as "data carriers", preferably with `final` fields to prevent mutability.

# Structure

The layered structure present in otr4j.

The `user (chat) app` adopts the functionality of `otr4j`. `user (chat) app` itself is not part of this project, but it does depend on `otr4j` for providing the functionality of the Off-the-Record protocol.

`otr4j` consists of a number of different packages. These packages are shortly discussed here. In-depth details for each package should be found in the package documentation (javadoc).

- `net.java.otr4j.api`: Classes that are part of the general otr4j api.
- `net.java.otr4j.crypto`: Classes that encapsulate low-level cryptographic logic to provide a simple, fool-proof API. In addition it abstracts away the actual crypto implementation logic.
- `net.java.otr4j.crypto.ed448`: Classes that encapsulate Ed448-Goldilocks elliptic curve.
- `net.java.otr4j.io`: Basic support for encoding and decoding according to OTR protocol.
- `net.java.otr4j.messages`: Full and partial messages used in OTR.
- `net.java.otr4j.session`: Management of the OTR protocol session.
- `net.java.otr4j.session.api`: Internal API to abstract away from exact Socialist Millionaire's Protocol implementation.
- `net.java.otr4j.session.ake`: OTRv2/3 AKE implementation. (State machine)
- `net.java.otr4j.session.smp`: OTRv2/3 Socialist Millionaire's Protocol (State machine)
- `net.java.otr4j.session.smpv4`: OTRv4 Socialist Millionaire's Protocol (State machine)
- `net.java.otr4j.session.state`: OTR messaging protocol states (State machine)
- `net.java.otr4j.util`: Utilities for otr4j.

```
+===================+
|  user (chat) app  |
+========+==========+
         |
         |
+--------v----------+
|   <<session>>     |
|      state        |
| ake | smp | smpv4 |
|       api         |
|-------------------|
|     messages      |
|-------------------|
|       io          |
|-------------------|
|       api         |
|-------------------|
|  util  |  crypto  |
+-------------------+
```

Packages must only depend on package on lower layers of the structure.

# Public API

`TODO: document what is part of the official public API.`

# Code layout rules

`TODO: describe the code layout rules that result in the current package structure and method distribution.`
