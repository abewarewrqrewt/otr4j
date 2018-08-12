/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import java.util.logging.Logger;

/**
 * OtrPolicy is an intelligent policy class that will return the current
 * policy's setting on various aspects. The policy object is intelligent enough
 * to adjust its answer to its composition. For example, if all OTR protocol
 * versions are denied, it will not return true to sending whitespace tags or
 * (re)starting AKE.
 *
 * @author George Politis
 */
// TODO consider removing OTRv1 methods altogether
public final class OtrPolicy {

    private static final Logger LOGGER = Logger.getLogger(OtrPolicy.class.getName());

    /**
     * Flag for indicating otr V1 is allowed in this policy.
     *
     * @deprecated OTR v1 is no longer supported.
     */
    @Deprecated
    public static final int ALLOW_V1 = 1;
    /**
     * Constant for flag indicating that OTR protocol version 2 is allowed.
     */
    public static final int ALLOW_V2 = 1 << 1;
    /**
     * Constant for flag indicating that encryption is required, i.e. prevent plaintext messages from being sent.
     */
    public static final int REQUIRE_ENCRYPTION = 1 << 2;
    /**
     * Constant for flag indicating that whitespace tags should be sent.
     */
    public static final int SEND_WHITESPACE_TAG = 1 << 3;
    /**
     * Constant for flag indicating that AKE should be started upon receiving a whitespace tag.
     */
    public static final int WHITESPACE_START_AKE = 1 << 4;
    /**
     * Constant for flag indicating that a new AKE should be started upon receiving an OTR error message.
     */
    public static final int ERROR_START_AKE = 1 << 5;
    /**
     * Constant for flag indicating that OTR protocol version 3 is allowed.
     */
    public static final int ALLOW_V3 = 1 << 6;
    /**
     * Constant for flag indicating that OTR protocol version 4 is allowed.
     */
    public static final int ALLOW_V4 = 1 << 7;

    /**
     * Constant for mask containing all supported OTR protocol versions.
     */
    public static final int VERSION_MASK = ALLOW_V2 | ALLOW_V3 | ALLOW_V4;

    // The four old version 1 policies correspond to the following combinations
    // of flags (adding an allowance for version 2 of the protocol):

    /**
     * Constant for completely disabling OTR by policy.
     */
    public static final int NEVER = 0x00;
    /**
     * Constant to define OTR policy that opportunistically initiates OTR.
     */
    public static final int OPPORTUNISTIC = ALLOW_V2 | ALLOW_V3 | ALLOW_V4
            | SEND_WHITESPACE_TAG | WHITESPACE_START_AKE | ERROR_START_AKE;
    /**
     * Constant to define OTR policy that only OTR should only be initiated upon manual request.
     */
    public static final int OTRL_POLICY_MANUAL = ALLOW_V2 | ALLOW_V3 | ALLOW_V4;
    /**
     * Constant to define policy that OTR should be used at all times. Therefore plaintext activity is not allowed.
     */
    public static final int OTRL_POLICY_ALWAYS = ALLOW_V2 | ALLOW_V3 | ALLOW_V4
            | REQUIRE_ENCRYPTION | WHITESPACE_START_AKE | ERROR_START_AKE;

    /**
     * Constant defining default OTR policy for otr4j.
     */
    public static final int OTRL_POLICY_DEFAULT = OPPORTUNISTIC;

    private int policy;

    /**
     * Create OTR policy instance based on NEVER profile.
     */
    public OtrPolicy() {
        this(NEVER);
    }

    /**
     * Create OTR policy instance based on provided policy value (bitset).
     *
     * @param policy The initial policy value.
     */
    public OtrPolicy(final int policy) {
        this.policy = policy;
    }

    /**
     * Get full policy value. Returns raw policy value containing composition of
     * bit flags.
     *
     * @return Returns the raw policy value.
     */
    public int getPolicy() {
        return policy;
    }

    /**
     * getAllowV1 is deprecated as OTR V1 is not supported anymore.
     *
     * @return Always returns false.
     * @deprecated OTR V1 is not supported anymore.
     */
    @Deprecated
    public boolean isAllowV1() {
        return false;
    }

    /**
     * Get OTR v2 policy.
     *
     * @return Returns true if OTR version 2 is allowed.
     */
    public boolean isAllowV2() {
        return (policy & OtrPolicy.ALLOW_V2) != 0;
    }

    /**
     * Get OTR v3 policy.
     *
     * @return Returns true if OTR version 3 is allowed.
     */
    public boolean isAllowV3() {
        return (policy & OtrPolicy.ALLOW_V3) != 0;
    }

    /**
     * Get OTR v4 policy.
     *
     * @return Returns true if OTR version 4 is allowed.
     */
    public boolean isAllowV4() {
        return (policy & OtrPolicy.ALLOW_V4) != 0;
    }

    /**
     * Policy regarding restarting AKE upon receiving an OTR Error message.
     *
     * The answer depends on whether at least one protocol version is enabled.
     * If all versions are denied, we will return false.
     *
     * @return Returns true if intention is to re-establish OTR encrypted
     * session immediately after receiving an error message. Returns false if
     * policy is set to false, or if no OTR protocol version is allowed.
     */
    public boolean isErrorStartAKE() {
        if (!viable()) {
            LOGGER.warning("Returning false to getErrorStartAKE as no OTR protocol version is allowed.");
            return false;
        }
        return (policy & OtrPolicy.ERROR_START_AKE) != 0;
    }

    /**
     * Require encryption to be used.
     *
     * @return Returns true if encryption needs to be used for any
     * communication, or false if message are allowed to be sent unencrypted in
     * case an OTR session is not established.
     */
    public boolean isRequireEncryption() {
        return (policy & OtrPolicy.REQUIRE_ENCRYPTION) != 0;
    }

    /**
     * Policy regarding automatically sending whitespace tag.
     *
     * The answer depends on whether at least one protocol version is enabled.
     * If all versions are denied, we will return false.
     *
     * @return Returns true if policy is set to send whitespace tags and at
     * least one OTR protocol version is allowed. Returns false if policy is set
     * to false, or if no OTR protocol version is allowed.
     */
    public boolean isSendWhitespaceTag() {
        if (!viable()) {
            LOGGER.warning("Returning false to getSendWhitespaceTag as no OTR protocol version is allowed.");
            return false;
        }
        return (policy & OtrPolicy.SEND_WHITESPACE_TAG) != 0;
    }

    /**
     * Policy regarding automatically initiating OTR encrypted session upon
     * receiving whitespace tag.
     *
     * The answer depends on whether at least one protocol version is enabled.
     * If all versions are denied, we will return false.
     *
     * @return Returns true if policy is set to initiate OTR encrypted session
     * and at least one OTR protocol version is allowed. Returns false if policy
     * is set to false, or if no OTR protocol version is allowed.
     */
    public boolean isWhitespaceStartAKE() {
        if (!viable()) {
            LOGGER.warning("Returning false to getWhitespaceStartAKE as no OTR protocol version is allowed.");
            return false;
        }
        return (policy & OtrPolicy.WHITESPACE_START_AKE) != 0;
    }

    /**
     * OTR V1 is not supported anymore. Calling this method will not change the policy.
     *
     * @param value value is ignored
     * @deprecated Support for OTR V1 is dropped.
     */
    @Deprecated
    public void setAllowV1(final boolean value) {
        // setAllowV1 is not supported anymore
    }

    /**
     * Set/unset ALLOW_V2 policy flag, indicating that OTR version 2 is allowed.
     *
     * @param value True to set, false to unset.
     */
    public void setAllowV2(final boolean value) {
        if (value) {
            policy |= ALLOW_V2;
        } else {
            policy &= ~ALLOW_V2;
        }
    }

    /**
     * Set/unset ALLOW_V3 policy flag, indicating that OTR version 3 is allowed.
     *
     * @param value True to set, false to unset.
     */
    public void setAllowV3(final boolean value) {
        if (value) {
            policy |= ALLOW_V3;
        } else {
            policy &= ~ALLOW_V3;
        }
    }

    /**
     * Set/unset ALLOW_V4 policy flag, indicating that OTR version 4 is allowed.
     *
     * @param value True to set, false to unset.
     */
    public void setAllowv4(final boolean value) {
        if (value) {
            policy |= ALLOW_V4;
        } else {
            policy &= ~ALLOW_V4;
        }
    }

    /**
     * Set ERROR_START_AKE flag, indicating that we should start a new AKE
     * negotiation upon receiving an OTR error message.
     *
     * @param value True to set, false to unset.
     */
    public void setErrorStartAKE(final boolean value) {
        if (value) {
            policy |= ERROR_START_AKE;
        } else {
            policy &= ~ERROR_START_AKE;
        }
    }

    /**
     * Set REQUIRE_ENCRYPTION flag, indicating that we should ensure an
     * encrypted session is established before allowing to pass through
     * messages.
     *
     * @param value True to set, false to unset.
     */
    public void setRequireEncryption(final boolean value) {
        if (value) {
            policy |= REQUIRE_ENCRYPTION;
        } else {
            policy &= ~REQUIRE_ENCRYPTION;
        }
    }

    /**
     * Set SEND_WHITESPACE_TAG flag, indicating that we should send a
     * whitespace tag once to test OTR capabilities/willingness of other party.
     *
     * @param value True to set, false to unset.
     */
    public void setSendWhitespaceTag(final boolean value) {
        if (value) {
            policy |= SEND_WHITESPACE_TAG;
        } else {
            policy &= ~SEND_WHITESPACE_TAG;
        }
    }

    /**
     * Set WHITESPACE_START_AKE flag, indicating that we should start an AKE
     * negotiation upon receiving a whitespace tag from the other party.
     *
     * @param value True to set, false to unset.
     */
    public void setWhitespaceStartAKE(final boolean value) {
        if (value) {
            policy |= WHITESPACE_START_AKE;
        } else {
            policy &= ~WHITESPACE_START_AKE;
        }
    }

    /**
     * Check with policy value to see whether or not all flags are set to
     * compose into the ENABLE_ALWAYS policy profile.
     *
     * @return Returns true in case full ENABLE_ALWAYS profile is active.
     */
    public boolean isEnableAlways() {
        return isEnableManual() && isErrorStartAKE() && isRequireEncryption() && isWhitespaceStartAKE();
    }

    /**
     * Set EnableAlways policy configuration.
     *
     * Pass in 'true' to enable 'EnableAlways' profile. 'false' does not have
     * any effect.
     *
     * @param value 'true' to enable EnableAlways policy.
     * @deprecated Deprecated. Please use {@link #setEnableAlways() } as passing
     * in 'false' for value does not make sense.
     */
    @Deprecated
    public void setEnableAlways(final boolean value) {
        if (!value) {
            LOGGER.warning("setEnableAlways(false) is not supported anymore. This action has no effect. Please switch to using the non-deprecated alternative in the future.");
            return;
        }
        setEnableAlways();
    }

    /**
     * Set EnableAlways policy configuration.
     */
    public void setEnableAlways() {
        setEnableManual();
        setRequireEncryption(true);
        setErrorStartAKE(true);
        setWhitespaceStartAKE(true);
    }

    /**
     * Get boolean indicating that ENABLE_MANUAL policy profile is active.
     *
     * @return Returns true if ENABLE_MANUAL is active, false otherwise.
     */
    public boolean isEnableManual() {
        return isAllowV2() && isAllowV3() && isAllowV4();
    }

    /**
     * Set EnableManual profile.
     *
     * @param value true to enable profile, false has no effect.
     * @deprecated This method is deprecated and replaced with {@link #setEnableManual() }.
     */
    @Deprecated
    public void setEnableManual(final boolean value) {
        if (!value) {
            LOGGER.warning("setEnableManual(false) is not supported anymore. This action has no effect. Please switch to using the non-deprecated alternative in the future.");
            return;
        }
        setEnableManual();
    }

    /**
     * Set EnableManual policy configuration.
     */
    public void setEnableManual() {
        setAllowV2(true);
        setAllowV3(true);
        setAllowv4(true);
    }

    /**
     * Check if the current policy is viable for starting OTR encrypted
     * sessions given the restrictions in the policy.
     *
     * @return Returns true if any supported OTR protocol version is enabled and
     * therefore we can set up an encrypted session with a client with
     * compatible policy. Returns false if no protocol version is enabled.
     */
    public boolean viable() {
        return isAllowV2() || isAllowV3() || isAllowV4();
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || obj.getClass() != this.getClass()) {
            return false;
        }
        final OtrPolicy policy = (OtrPolicy) obj;
        return policy.policy == this.policy;
    }

    @Override
    public int hashCode() {
        return this.policy;
    }
}
