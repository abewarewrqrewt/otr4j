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
// * point-comparison (greater-than-or-equal, at the very least)
// * OPTIONAL: access to base point, modulus, prime-order?
// FIXME update package-import-constraint to new packages.
// FIXME verify that new ed448 crypto implementations do not litter memory space with temporary data. Check cloned arrays, appropriate memory cleaning, etc.
