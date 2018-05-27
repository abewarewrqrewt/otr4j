/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.api;

import java.util.Set;

import static org.junit.Assert.*;
import org.junit.Test;

/**
 * Tests for OtrPolicyUtil.
 *
 * @author Danny van Heumen
 */
public class OtrPolicyUtilTest {

    public OtrPolicyUtilTest() {
    }

    @Test(expected = NullPointerException.class)
    public void testAllowedVersionsNullPolicy() {
        OtrPolicyUtil.allowedVersions(null);
    }

    @Test
    public void testAllowedVersionsDefaultPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OTRL_POLICY_DEFAULT);
        final Set<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(3, versions.size());
        assertTrue(versions.contains(Session.OTRv.TWO));
        assertTrue(versions.contains(Session.OTRv.THREE));
        assertTrue(versions.contains(Session.OTRv.FOUR));
    }

    @Test
    public void testAllowedVersionsNoVersionPolicy() {
        final OtrPolicy policy = new OtrPolicy(0);
        final Set<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(0, versions.size());
    }

    @Test
    public void testAllowedVersionsMinimalPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V3);
        final Set<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(1, versions.size());
        assertTrue(versions.contains(Session.OTRv.THREE));
    }

    @Test
    public void testAllowedVersionsCustomPolicy() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3 | OtrPolicy.WHITESPACE_START_AKE);
        final Set<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(2, versions.size());
        assertTrue(versions.contains(Session.OTRv.TWO));
        assertTrue(versions.contains(Session.OTRv.THREE));
    }

    @Test
    public void testAllowedVersionOneHasNoEffect() {
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.ALLOW_V1);
        final Set<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        assertEquals(0, versions.size());
    }
}
