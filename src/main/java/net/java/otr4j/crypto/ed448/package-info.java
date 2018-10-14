/**
 * Package containing wrapper classes for the external Ed448-Goldilocks support.
 *
 * Types in this package are fine-tuned to the definitions of OTRv4.
 */
package net.java.otr4j.crypto.ed448;
// FIXME replace Joldilocks with BC 1.60+. Requires:
// * 'Is identity' check
// * 'Is on curve' check
// * multiply-by-base operation
// * multiply-by-(arbitrary)-point operation.
// * addition-operation
// * negation-operation
// * point-comparison (greater-than, at the very least)
// * OPTIONAL: access to modulus constant
// * OPTIONAL: access to prime-order constant
// FIXME transition to byte-arrays for internal (persistent) representations of Scalars and Points
// FIXME update package-import-constraint to new packages.
