package net.java.otr4j.api;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class OtrPolicyTest {

    private Level originalLoggingLevel;

    @Before
    public void setUp() {
        final Logger logger = Logger.getLogger(OtrPolicy.class.getName());
        originalLoggingLevel = logger.getLevel();
        logger.setLevel(Level.OFF);
    }

    @After
    public void tearDown() {
        Logger.getLogger(OtrPolicy.class.getName()).setLevel(originalLoggingLevel);
    }

    @Test
    public void testViablePolicyOTRv2Andv3() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3 | OtrPolicy.WHITESPACE_START_AKE);
        assertTrue(policy.viable());
    }

    @Test
    public void testViablePolicyOTRv2Only() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2);
        assertTrue(policy.viable());
    }

    @Test
    public void testViablePolicyOTRv3Only() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertTrue(policy.viable());
    }

    @Test
    public void testViablePolicyOTRv4Only() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V4);
        assertTrue(policy.viable());
    }

    @Test
    public void testViablePolicyNone() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.WHITESPACE_START_AKE | OtrPolicy.SEND_WHITESPACE_TAG);
        assertFalse(policy.viable());
    }

    @Test
    public void testViablePolicyOpportunistic() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        assertTrue(policy.viable());
    }

    @Test
    public void testV1NeverAllowed() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V1);
        assertFalse(policy.isAllowV1());
    }

    @Test
    public void testAllowV2Policy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2);
        assertTrue(policy.isAllowV2());
    }

    @Test
    public void testAllowV3Policy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertTrue(policy.isAllowV3());
    }

    @Test
    public void testAllowV4Policy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V4);
        assertTrue(policy.isAllowV4());
    }

    @Test
    public void testConditionalStartAKEAfterErrorPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertFalse(policy.isErrorStartAKE());
        policy.setErrorStartAKE(true);
        assertTrue(policy.isErrorStartAKE());
        policy.setAllowV3(false);
        assertFalse(policy.isErrorStartAKE());
    }

    @Test
    public void testConditionalSendWhitespacePolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertFalse(policy.isSendWhitespaceTag());
        policy.setSendWhitespaceTag(true);
        assertTrue(policy.isSendWhitespaceTag());
        policy.setAllowV3(false);
        assertFalse(policy.isSendWhitespaceTag());
    }

    @Test
    public void testConditionalWhitespaceStartAKEPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        assertFalse(policy.isWhitespaceStartAKE());
        policy.setWhitespaceStartAKE(true);
        assertTrue(policy.isWhitespaceStartAKE());
        policy.setAllowV3(false);
        assertFalse(policy.isWhitespaceStartAKE());
    }

    @Test
    public void testRequireEncryptionWithAllowedProtocols() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OTRL_POLICY_ALWAYS);
        policy.setAllowV2(false);
        policy.setAllowV3(false);
        policy.setAllowv4(false);
        assertTrue(policy.isRequireEncryption());
    }

    @Test
    public void testSetEnableAlwaysDeprecated() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.NEVER);
        assertFalse(policy.isAllowV2());
        assertFalse(policy.isAllowV3());
        assertFalse(policy.isAllowV4());
        assertFalse(policy.isRequireEncryption());
        assertFalse(policy.isWhitespaceStartAKE());
        assertFalse(policy.isErrorStartAKE());
        assertFalse(policy.isEnableAlways());
        policy.setEnableAlways(true);
        assertTrue(policy.isAllowV2());
        assertTrue(policy.isAllowV3());
        assertTrue(policy.isAllowV4());
        assertTrue(policy.isRequireEncryption());
        assertTrue(policy.isWhitespaceStartAKE());
        assertTrue(policy.isErrorStartAKE());
        assertTrue(policy.isEnableAlways());
    }

    @Test
    public void testSetEnableAlways() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.NEVER);
        assertFalse(policy.isAllowV2());
        assertFalse(policy.isAllowV3());
        assertFalse(policy.isAllowV4());
        assertFalse(policy.isRequireEncryption());
        assertFalse(policy.isWhitespaceStartAKE());
        assertFalse(policy.isErrorStartAKE());
        assertFalse(policy.isEnableAlways());
        policy.setEnableAlways();
        assertTrue(policy.isAllowV2());
        assertTrue(policy.isAllowV3());
        assertTrue(policy.isAllowV4());
        assertTrue(policy.isRequireEncryption());
        assertTrue(policy.isWhitespaceStartAKE());
        assertTrue(policy.isErrorStartAKE());
        assertTrue(policy.isEnableAlways());
    }

    @Test
    public void testEnableManual() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.NEVER);
        assertFalse(policy.isAllowV2());
        assertFalse(policy.isAllowV3());
        policy.setEnableManual();
        assertTrue(policy.isAllowV2());
        assertTrue(policy.isAllowV3());
        assertTrue(policy.isAllowV4());
        assertTrue(policy.isEnableManual());
    }
}
