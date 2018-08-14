package net.java.otr4j.api;

import net.java.otr4j.api.Session.OTRv;
import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.messages.ClientProfilePayload;
import net.java.otr4j.test.TestStrings;
import net.java.otr4j.util.BlockingSubmitter;
import net.java.otr4j.util.ConditionalBlockingQueue;
import net.java.otr4j.util.ConditionalBlockingQueue.Predicate;
import org.junit.Before;
import org.junit.Test;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.Integer.MAX_VALUE;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V2;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V3;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V4;
import static net.java.otr4j.api.OtrPolicy.OPPORTUNISTIC;
import static net.java.otr4j.api.OtrPolicy.OTRL_POLICY_MANUAL;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.FINISHED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.session.OtrSessionManager.createSession;
import static net.java.otr4j.util.BlockingQueuesTestUtils.rearrangeFragments;
import static net.java.otr4j.util.BlockingQueuesTestUtils.shuffle;
import static org.bouncycastle.util.encoders.Base64.toBase64String;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;

// FIXME test what happens when fragments are dropped.
public class SessionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Before
    public void setUp() {
        Logger.getLogger("").setLevel(Level.INFO);
    }

    @Test
    public void testEstablishedMixedVersionSessionsAliceClientInitiated() throws OtrException {
        final Conversation c = new Conversation(2);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V3 | ALLOW_V4));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(2);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V2 | ALLOW_V3), RANDOM, c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);

        // Start setting up an encrypted session.
        c.clientAlice.session.startSession();
        // Expecting Query message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        // Expecting Identity message from Bob, DH-Commit message from Bob 2.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        // Expecting Auth-R message, DH-Key message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(OTRv.FOUR, c.clientBob.session.getOutgoingSession().getProtocolVersion());
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        // Expecting Auth-I message from Bob, Signature message from Bob 2.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(c.clientBob.session.getSenderInstanceTag()));
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob2.session.getSenderInstanceTag()));
        // Expecting DAKE data message, Reveal Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        assertEquals(OTRv.THREE, bob2.session.getOutgoingSession().getProtocolVersion());

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        c.clientAlice.session.setOutgoingSession(bob2.session.getSenderInstanceTag());
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertEquals(msg1, bob2.receiveMessage());
        assertNull(c.clientBob.receiveMessage());

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
    }

    @Test
    public void testEstablishedMixedVersionSessionsAliceClientInitiatedFragmented() throws OtrException, ProtocolException {
        final Conversation c = new Conversation(MAX_VALUE, 150);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V3 | ALLOW_V4));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(MAX_VALUE);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V2 | ALLOW_V3), RANDOM, c.submitterAlice, bob2Channel);
        bob2.setMessageSize(150);
        c.submitterBob.addQueue(bob2Channel);

        // Start setting up an encrypted session.
        c.clientAlice.session.startSession();
        // Expecting Query message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        // Expecting Identity message from Bob, DH-Commit message from Bob 2.
        rearrangeFragments(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting Auth-R message, DH-Key message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(OTRv.FOUR, c.clientBob.session.getOutgoingSession().getProtocolVersion());
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        // Expecting Auth-I message from Bob, Signature message from Bob 2.
        rearrangeFragments(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(c.clientBob.session.getSenderInstanceTag()));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob2.session.getSenderInstanceTag()));
        // Expecting DAKE data message, Reveal Signature message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        assertEquals(OTRv.THREE, bob2.session.getOutgoingSession().getProtocolVersion());

        // Due to 2 sessions being set up at the same time, either one can be established first. The first session is
        // automatically chosen to be the default session, so we need to manually set our chosen session as default
        // outgoing session.
        c.clientAlice.session.setOutgoingSession(c.clientBob.session.getSenderInstanceTag());
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[]{msg1}, c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        c.clientAlice.session.setOutgoingSession(bob2.session.getSenderInstanceTag());
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[]{msg1}, bob2.receiveAllMessages(true));
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
    }

    @Test
    public void testEstablishedMixedVersionSessionsBobsClientInitiates() throws OtrException {
        final Conversation c = new Conversation(2);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(2);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V3 | ALLOW_V4), RANDOM, c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);

        // Start setting up an encrypted session.
        c.clientBob.sendMessage(TestStrings.otrQuery);
        assertNull(c.clientAlice.receiveMessage());
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        // Expecting DH-Key message from both of Bob's clients.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(OTRv.THREE, c.clientBob.session.getOutgoingSession().getProtocolVersion());
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        // TODO there is an issue with the OTR protocol such that acting on a received DH-Commit message skips the check of whether higher versions of the OTR protocol are available. (Consider not responding unless a query tag was previously sent.)
        assertEquals(OTRv.THREE, bob2.session.getOutgoingSession().getProtocolVersion());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(c.clientBob.session.getSenderInstanceTag()));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob2.session.getSenderInstanceTag()));

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
    }

    @Test
    public void testMultipleSessions() throws OtrException {
        final OtrPolicy policy = new OtrPolicy(ALLOW_V2 | ALLOW_V3 | OtrPolicy.ERROR_START_AKE & ~ALLOW_V4);
        final Conversation c = new Conversation(3);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(policy);
        c.clientBob.setPolicy(policy);
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(3);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, policy, RANDOM, c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);
        final LinkedBlockingQueue<String> bob3Channel = new LinkedBlockingQueue<>(3);
        final Client bob3 = new Client("Bob 3", c.sessionIDBob, policy, RANDOM, c.submitterAlice, bob3Channel);
        c.submitterBob.addQueue(bob3Channel);

        // Start setting up an encrypted session.
        c.clientBob.sendMessage(TestStrings.otrQuery);
        assertNull(c.clientAlice.receiveMessage());
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());
        // Expecting DH-Key message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(c.clientBob.receiveMessage());
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());
        assertNull(bob3.receiveMessage());
        assertNull(bob3.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        assertEquals(ENCRYPTED, bob3.session.getSessionStatus());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(c.clientBob.session.getSenderInstanceTag()));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob2.session.getSenderInstanceTag()));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob3.session.getSenderInstanceTag()));

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertNotEquals(msg1, bob3.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());

        // Continue conversation with first of Bob's clients.
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertEquals(msg2, c.clientAlice.receiveMessage());

        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg3, bob2.receiptChannel.peek());
        assertNotEquals(msg3, bob3.receiptChannel.peek());
        assertEquals(msg3, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());

        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertEquals(msg4, c.clientAlice.receiveMessage());

        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg5, bob2.receiptChannel.peek());
        assertNotEquals(msg5, bob3.receiptChannel.peek());
        assertEquals(msg5, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientBob.session.endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(FINISHED, c.clientAlice.session.getSessionStatus());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        assertEquals(ENCRYPTED, bob3.session.getSessionStatus());

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
        assertEquals(0, bob3.receiptChannel.size());
    }

    @Test
    public void testQueryStart() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientAlice.setPolicy(new OtrPolicy(OPPORTUNISTIC & ~ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OPPORTUNISTIC & ~ALLOW_V4));
        c.clientBob.sendMessage(TestStrings.otrQuery);
        assertNull(c.clientAlice.receiveMessage());
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage());
        // Expecting DH-Key message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertEquals(msg2, c.clientAlice.receiveMessage());
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertEquals(msg3, c.clientBob.receiveMessage());
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertEquals(msg4, c.clientAlice.receiveMessage());
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertEquals(msg5, c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientBob.session.endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Bob has not yet switched session status as he has not processed the message yet.
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testForcedStart() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientAlice.setPolicy(new OtrPolicy(OTRL_POLICY_MANUAL & ~ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OTRL_POLICY_MANUAL & ~ALLOW_V4));
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting DH-Commit message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting DH-Key message from Alice.
        assertNull(c.clientBob.receiveMessage());
        // Expecting Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting Reveal Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertEquals(msg2, c.clientAlice.receiveMessage());
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertEquals(msg3, c.clientBob.receiveMessage());
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertEquals(msg4, c.clientAlice.receiveMessage());
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertEquals(msg5, c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientBob.session.endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Bob has not yet switched session status as he has not processed the message yet.
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testPlaintext() throws OtrException {
        final Conversation c = new Conversation(1);
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertEquals(msg1, c.clientBob.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(msg2);
        assertEquals(msg2, c.clientAlice.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(msg3);
        assertEquals(msg3, c.clientBob.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(msg4);
        assertEquals(msg4, c.clientAlice.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(msg5);
        assertEquals(msg5, c.clientBob.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        c.clientBob.session.endSession();
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testPlainTextMessagingNewClients() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("hello world");
        assertEquals("hello world", c.clientAlice.receiveMessage());
        c.clientAlice.sendMessage("hello bob");
        assertEquals("hello bob", c.clientBob.receiveMessage());
    }

    @Test
    public void testEstablishOTR4Session() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        assertNull(c.clientBob.receiveMessage());
        c.clientBob.sendMessage("Hello Alice!");
        assertEquals("Hello Alice!", c.clientAlice.receiveMessage());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertNull(c.clientBob.receiveMessage());
        assertEquals(FINISHED, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionFragmented() throws OtrException {
        final Conversation c = new Conversation(20, 150);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        assertNull(c.clientBob.receiveMessage());
    }

    @Test
    public void testOTR4ExtensiveMessagingToVerifyRatcheting() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        assertNull(c.clientBob.receiveMessage());

        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(300);
            c.clientBob.sendMessage(messageBob);
            assertMessage("Iteration: " + i + ", message Bob: " + messageBob, messageBob, c.clientAlice.receiveMessage());
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(300);
            c.clientAlice.sendMessage(messageAlice);
            assertMessage("Iteration: " + i + ", message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage());
        }
    }

    @Test
    public void testOTR4ExtensiveMessagingToVerifyRatchetingManyConsecutiveMessages() throws OtrException {
        final Conversation c = new Conversation(25);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        assertNull(c.clientBob.receiveMessage());

        final String[] messages = new String[25];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = randomMessage(300);
        }
        // Bob sending many messages
        for (int i = 0; i < 25; i++) {
            c.clientBob.sendMessage(messages[i]);
        }
        for (final String message : messages) {
            assertMessage("Message Bob: " + message, message, c.clientAlice.receiveMessage());
        }
        // Alice sending one message in response
        final String messageAlice = "Man, you talk a lot!";
        c.clientAlice.sendMessage(messageAlice);
        assertMessage("Message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage());
    }

    @Test
    public void testOTR4ExtensiveMessagingFragmentation() throws OtrException {
        final Conversation c = new Conversation(20, 150);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        assertEquals(0, c.clientBob.receiveAllMessages(true).length);

        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(1, 500);
            c.clientBob.sendMessage(messageBob);
            assertArrayEquals("Iteration: " + i + ", message Bob: " + messageBob,
                new String[]{messageBob}, c.clientAlice.receiveAllMessages(true));
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(1, 500);
            c.clientAlice.sendMessage(messageAlice);
            assertArrayEquals("Iteration: " + i + ", message Alice: " + messageAlice,
                new String[]{messageAlice}, c.clientBob.receiveAllMessages(true));
        }
    }

    @Test
    public void testOTR4ExtensiveMessagingFragmentationShuffled() throws OtrException {
        final Conversation c = new Conversation(20, 150);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        shuffle(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        shuffle(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        shuffle(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        shuffle(c.clientBob.receiptChannel, RANDOM);
        assertEquals(0, c.clientBob.receiveAllMessages(true).length);

        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(1, 500);
            c.clientBob.sendMessage(messageBob);
            shuffle(c.clientAlice.receiptChannel, RANDOM);
            assertArrayEquals("Iteration: " + i + ", message Bob: " + messageBob,
                new String[]{messageBob}, c.clientAlice.receiveAllMessages(true));
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(1, 500);
            c.clientAlice.sendMessage(messageAlice);
            shuffle(c.clientBob.receiptChannel, RANDOM);
            assertArrayEquals("Iteration: " + i + ", message Alice: " + messageAlice,
                new String[]{messageAlice}, c.clientBob.receiveAllMessages(true));
        }
    }

    @Test
    public void testOTR4SmallConversationWithHugeMessages() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        assertNull(c.clientBob.receiveMessage());

        for (int i = 0; i < 5; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(1000000);
            c.clientBob.sendMessage(messageBob);
            assertMessage("Iteration: " + i + ", message Bob: " + messageBob, messageBob, c.clientAlice.receiveMessage());
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(1000000);
            c.clientAlice.sendMessage(messageAlice);
            assertMessage("Iteration: " + i + ", message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage());
        }
    }

    private static void assertMessage(final String message, final String expected, final String actual) {
        if (expected.length() == 0) {
            assertNull(message, actual);
        } else {
            assertEquals(message, expected, actual);
        }
    }

    private static String randomMessage(final int maxLength) {
        return randomMessage(0, maxLength);
    }

    private static String randomMessage(final int minLength, final int maxLength) {
        final byte[] arbitraryContent = new byte[minLength + RANDOM.nextInt(maxLength - minLength)];
        RANDOM.nextBytes(arbitraryContent);
        return toBase64String(arbitraryContent);
    }

    /**
     * Dummy conversation implementation, mimicking a conversation between two parties.
     */
    private static final class Conversation {

        private final SessionID sessionIDAlice;
        private final SessionID sessionIDBob;

        private final Client clientAlice;
        private final Client clientBob;

        private final BlockingSubmitter<String> submitterBob;
        private final BlockingSubmitter<String> submitterAlice;

        /**
         * Constructor with defaults: Unlimited-length messages.
         */
        private Conversation(final int channelCapacity) {
            final LinkedBlockingQueue<String> directChannelAlice = new LinkedBlockingQueue<>(channelCapacity);
            submitterAlice = new BlockingSubmitter<>();
            submitterAlice.addQueue(directChannelAlice);
            final LinkedBlockingQueue<String> directChannelBob = new LinkedBlockingQueue<>(channelCapacity);
            submitterBob = new BlockingSubmitter<>();
            submitterBob.addQueue(directChannelBob);
            this.sessionIDBob = new SessionID("bob@InMemoryNetwork4", "alice@InMemoryNetwork4",
                "InMemoryNetwork4");
            this.sessionIDAlice = new SessionID("alice@InMemoryNetwork4", "bob@InMemoryNetwork4",
                "InMemoryNetwork4");
            this.clientBob = new Client("Bob", sessionIDBob, new OtrPolicy(OTRL_POLICY_MANUAL), RANDOM,
                submitterAlice, directChannelBob);
            this.clientAlice = new Client("Alice", sessionIDAlice, new OtrPolicy(OTRL_POLICY_MANUAL),
                RANDOM, submitterBob, directChannelAlice);
        }

        /**
         * Constructor with configurable maximum message size and channel capacity (maximum number of messages
         * simultaneously stored).
         *
         * @param maxMessageSize  Maximum size of message allowed.
         * @param channelCapacity Maximum number of messages allowed to be in transit simultaneously.
         */
        private Conversation(final int channelCapacity, final int maxMessageSize) {
            final Predicate<String> condition = new MaxMessageSize(maxMessageSize);
            final ConditionalBlockingQueue<String> directChannelAlice = new ConditionalBlockingQueue<>(condition,
                new LinkedBlockingQueue<String>(channelCapacity));
            submitterAlice = new BlockingSubmitter<>();
            submitterAlice.addQueue(directChannelAlice);
            final ConditionalBlockingQueue<String> directChannelBob = new ConditionalBlockingQueue<>(condition,
                new LinkedBlockingQueue<String>(channelCapacity));
            submitterBob = new BlockingSubmitter<>();
            submitterBob.addQueue(directChannelBob);
            this.sessionIDBob = new SessionID("bob@InMemoryNetwork4", "alice@InMemoryNetwork4",
                "InMemoryNetwork4");
            this.sessionIDAlice = new SessionID("alice@InMemoryNetwork4", "bob@InMemoryNetwork4",
                "InMemoryNetwork4");
            this.clientBob = new Client("Bob", sessionIDBob, new OtrPolicy(OTRL_POLICY_MANUAL), RANDOM,
                submitterAlice, directChannelBob);
            this.clientBob.setMessageSize(maxMessageSize);
            this.clientAlice = new Client("Alice", sessionIDAlice, new OtrPolicy(OTRL_POLICY_MANUAL),
                RANDOM, submitterBob, directChannelAlice);
            this.clientAlice.setMessageSize(maxMessageSize);
        }
    }

    /**
     * Predicate to verify maximum message size.
     */
    private static final class MaxMessageSize implements Predicate<String> {
        private final int maximum;

        private MaxMessageSize(final int maximum) {
            this.maximum = maximum;
        }

        @Override
        public boolean test(@Nonnull final String s) {
            return s.length() <= maximum;
        }
    }

    /**
     * Dummy client implementation for use with OTRv4 protocol tests.
     */
    // FIXME naming for consistency between field name, method name, type name.
    private static final class Client implements OtrEngineHost {

        private final Logger logger;

        private final KeyPair dsaKeyPair;

        private final EdDSAKeyPair ed448KeyPair;

        private final BlockingSubmitter<String> sendChannel;

        private final BlockingQueue<String> receiptChannel;

        private final ClientProfilePayload profilePayload;

        private final Session session;

        private OtrPolicy policy;

        private int messageSize = MAX_VALUE;

        private Client(@Nonnull final String id, @Nonnull final SessionID sessionID, @Nonnull final OtrPolicy policy,
                       @Nonnull final SecureRandom random, @Nonnull final BlockingSubmitter<String> sendChannel,
                       @Nonnull final BlockingQueue<String> receiptChannel) {
            this.logger = Logger.getLogger(Client.class.getName() + ":" + id);
            this.ed448KeyPair = EdDSAKeyPair.generate(random);
            this.dsaKeyPair = OtrCryptoEngine.generateDSAKeyPair();
            this.receiptChannel = requireNonNull(receiptChannel);
            this.sendChannel = requireNonNull(sendChannel);
            this.policy = requireNonNull(policy);
            final Calendar expirationCalendar = Calendar.getInstance();
            expirationCalendar.add(Calendar.DAY_OF_YEAR, 7);
            final InstanceTag senderInstanceTag = InstanceTag.random(random);
            final ClientProfile profile = new ClientProfile(senderInstanceTag, this.ed448KeyPair.getPublicKey(),
                Collections.singleton(OTRv.FOUR), expirationCalendar.getTimeInMillis() / 1000, null);
            this.profilePayload = ClientProfilePayload.sign(profile, null, this.ed448KeyPair);
            this.session = createSession(sessionID, this, senderInstanceTag);
        }

        void setMessageSize(final int messageSize) {
            this.messageSize = messageSize;
        }

        String receiveMessage() throws OtrException {
            final String msg = this.receiptChannel.remove();
            return this.session.transformReceiving(msg);
        }

        String[] receiveAllMessages(final boolean skipNulls) throws OtrException {
            final ArrayList<String> messages = new ArrayList<>();
            this.receiptChannel.drainTo(messages);
            final ArrayList<String> results = new ArrayList<>();
            for (final String msg : messages) {
                final String result = this.session.transformReceiving(msg);
                if (result == null && skipNulls) {
                    continue;
                }
                results.add(result);
            }
            return results.toArray(new String[0]);
        }

        void sendMessage(@Nonnull final String msg) throws OtrException {
            this.sendChannel.addAll(Arrays.asList(this.session.transformSending(msg)));
        }

        void setPolicy(final OtrPolicy policy) {
            this.policy = requireNonNull(policy);
        }

        @Override
        public void injectMessage(@Nonnull final SessionID sessionID, @Nonnull final String msg) {
            this.sendChannel.add(msg);
        }

        @Override
        public void unreadableMessageReceived(@Nonnull final SessionID sessionID) {
            logger.finest("Unreadable message received. (Session: " + sessionID + ")");
        }

        @Override
        public void unencryptedMessageReceived(@Nonnull final SessionID sessionID, @Nonnull final String msg) {
            logger.finest("Message received unencrypted: " + msg + " (Session: " + sessionID + ")");
        }

        @Override
        public void showError(@Nonnull final SessionID sessionID, @Nonnull final String error) {
            logger.finest("OTR received an error: " + error + " (Session: " + sessionID + ")");
        }

        @Override
        public void finishedSessionMessage(@Nonnull final SessionID sessionID, @Nonnull final String msgText) {
            logger.finest("Encrypted session finished. (Session: " + sessionID + ")");
        }

        @Override
        public void requireEncryptedMessage(@Nonnull final SessionID sessionID, @Nonnull final String msgText) {
            logger.finest("Encrypted message is required. (Session: " + sessionID + "). Sent in plain text: " + msgText);
        }

        @Override
        public OtrPolicy getSessionPolicy(@Nonnull final SessionID sessionID) {
            return this.policy;
        }

        @Override
        public int getMaxFragmentSize(@Nonnull final SessionID sessionID) {
            return this.messageSize;
        }

        @Nonnull
        @Override
        public KeyPair getLocalKeyPair(@Nonnull final SessionID sessionID) {
            return this.dsaKeyPair;
        }

        @Nonnull
        @Override
        public EdDSAKeyPair getLongTermKeyPair(@Nonnull final SessionID sessionID) {
            return this.ed448KeyPair;
        }

        @Nonnull
        @Override
        public ClientProfilePayload getClientProfile(@Nonnull final SessionID sessionID) {
            return this.profilePayload;
        }

        @Override
        public void askForSecret(@Nonnull final SessionID sessionID, @Nonnull final InstanceTag receiverTag, @Nullable final String question) {
            throw new UnsupportedOperationException("To be implemented");
        }

        @Nonnull
        @Override
        public byte[] getLocalFingerprintRaw(@Nonnull final SessionID sessionID) {
            return OtrCryptoEngine.getFingerprintRaw((DSAPublicKey) this.dsaKeyPair.getPublic());
        }

        @Override
        public void smpError(@Nonnull final SessionID sessionID, final int tlvType, final boolean cheated) {
            logger.finest("SMP process resulted in error. (TLV type: " + tlvType + ", cheated: " + cheated + ", session: " + sessionID + ")");
        }

        @Override
        public void smpAborted(@Nonnull final SessionID sessionID) {
            logger.finest("SMP process is aborted. (Session: " + sessionID + ")");
        }

        @Override
        public void verify(@Nonnull final SessionID sessionID, @Nonnull final String fingerprint) {
            logger.finest("Verifying fingerprint " + fingerprint + " (Session: " + sessionID + ") [NOT IMPLEMENTED, LOGGING ONLY]");
        }

        @Override
        public void unverify(@Nonnull final SessionID sessionID, @Nonnull final String fingerprint) {
            logger.finest("Invalidating fingerprint " + fingerprint + " (Session: " + sessionID + ") [NOT IMPLEMENTED, LOGGING ONLY]");
        }

        @Override
        public String getReplyForUnreadableMessage(@Nonnull final SessionID sessionID) {
            return "The message is unreadable. (Session: " + sessionID + ")";
        }

        @Override
        public String getFallbackMessage(@Nonnull final SessionID sessionID) {
            return null;
        }

        @Override
        public void messageFromAnotherInstanceReceived(@Nonnull final SessionID sessionID) {
            logger.finest("Message from another instance received. (Session: " + sessionID + ")");
        }

        @Override
        public void multipleInstancesDetected(@Nonnull final SessionID sessionID) {
            logger.finest("Multiple instances detected. (Session: " + sessionID + ")");
        }

        @Override
        public void extraSymmetricKeyDiscovered(@Nonnull final SessionID sessionID, @Nonnull final String message, @Nonnull final byte[] extraSymmetricKey, @Nonnull final byte[] tlvData) {
            logger.finest("Extra symmetric key TLV discovered in encoded message. (Session: " + sessionID + ")");
        }
    }
}
