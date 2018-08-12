package net.java.otr4j.api;

import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.messages.ClientProfilePayload;
import net.java.otr4j.test.TestStrings;
import net.java.otr4j.test.dummyclient.DummyClient;
import net.java.otr4j.test.dummyclient.PriorityServer;
import net.java.otr4j.test.dummyclient.ProcessedTestMessage;
import net.java.otr4j.test.dummyclient.Server;
import net.java.otr4j.util.BlockingSubmitter;
import net.java.otr4j.util.ConditionalBlockingQueue;
import net.java.otr4j.util.ConditionalBlockingQueue.Predicate;
import org.junit.Before;
import org.junit.Test;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
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

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.session.OtrSessionManager.createSession;
import static net.java.otr4j.util.BlockingQueues.shuffle;
import static org.bouncycastle.util.encoders.Base64.toBase64String;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

// FIXME add test to prove that interchanged message fragments from multiple sender instances can be successfully reassembled. (This is a probably bug in previous OtrAssembler implementation/use.)
// FIXME add test to prove that OTRv2, OTRv3 and OTRv4 can be used interchangeably.
// FIXME add test to prove that OTRv2, OTRv3 and OTRv4 message fragments can be sent interchangeably as long as different sender instances are involved.
// TODO restructure existing OTRv3 tests as they now cause annoying hard-to-debug problems.
// FIXME test what happens when fragments are dropped.
public class SessionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Before
    public void setUp() {
        Logger.getLogger("").setLevel(Level.INFO);
    }
    
    @Test
    public void testMultipleSessions() throws Exception {
        DummyClient bob1 = new DummyClient("Bob@Wonderland");
        bob1.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                | OtrPolicy.ERROR_START_AKE));

        DummyClient bob2 = new DummyClient("Bob@Wonderland");
        bob2.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                | OtrPolicy.ERROR_START_AKE));

        DummyClient bob3 = new DummyClient("Bob@Wonderland");
        bob3.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                | OtrPolicy.ERROR_START_AKE));

        DummyClient alice = new DummyClient("Alice@Wonderland");
        alice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                | OtrPolicy.ERROR_START_AKE));

        Server server = new PriorityServer();
        alice.connect(server);
        bob1.connect(server);
        bob2.connect(server);
        bob3.connect(server);

        bob1.send(alice.getAccount(), TestStrings.otrQuery);

        alice.pollReceivedMessage(); // Query
        bob1.pollReceivedMessage(); // DH-Commit
        alice.pollReceivedMessage(); // DH-Key
        bob1.pollReceivedMessage(); // Reveal signature
        alice.pollReceivedMessage(); // Signature

        String msg;

        alice.send(
                bob1.getAccount(),
                msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob1.pollReceivedMessage().getContent());

        bob2.send(alice.getAccount(), msg = TestStrings.anotherOtrQuery);

        alice.pollReceivedMessage();
        bob2.pollReceivedMessage();
        alice.pollReceivedMessage();
        bob2.pollReceivedMessage();
        alice.pollReceivedMessage();

        bob2.send(alice.getAccount(), msg = "This should be encrypted !");
        assertThat("Message has been transferred unencrypted.", bob2
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, alice.pollReceivedMessage().getContent());

        bob3.send(alice.getAccount(), msg = TestStrings.yetAnotherOtrQuery);
        alice.pollReceivedMessage();
        bob3.pollReceivedMessage();
        alice.pollReceivedMessage();
        bob3.pollReceivedMessage();
        alice.pollReceivedMessage();

        bob3.send(alice.getAccount(), msg = "This should be encrypted !");
        assertThat("Message has been transferred unencrypted.", bob3
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, alice.pollReceivedMessage().getContent());

        bob1.send(alice.getAccount(),
                msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
        assertThat("Message has been transferred unencrypted.", bob1
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, alice.pollReceivedMessage().getContent());

        alice.send(bob1.getAccount(), msg = "Oh, is that all?");
        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob1.pollReceivedMessage().getContent());

        bob1.send(
                alice.getAccount(),
                msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
        assertThat("Message has been transferred unencrypted.", bob1
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, alice.pollReceivedMessage().getContent());

        alice.send(bob1.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob1.pollReceivedMessage().getContent());

        bob1.exit();
        alice.exit();
    }

    @Test
    public void testQueryStart() throws Exception {
        DummyClient[] convo = DummyClient.getConversation();
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];

        bob.send(alice.getAccount(), TestStrings.otrQuery);

        alice.pollReceivedMessage(); // Query
        bob.pollReceivedMessage(); // DH-Commit
        alice.pollReceivedMessage(); // DH-Key
        bob.pollReceivedMessage(); // Reveal signature
        alice.pollReceivedMessage(); // Signature

        assertEquals("The session is not encrypted.", SessionStatus.ENCRYPTED,
                bob.getSession().getSessionStatus());
        assertEquals("The session is not encrypted.", SessionStatus.ENCRYPTED,
                alice.getSession().getSessionStatus());

        String msg;

        alice.send(
                bob.getAccount(),
                msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob.pollReceivedMessage().getContent());

        bob.send(alice.getAccount(),
                msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
        assertThat("Message has been transferred unencrypted.", bob
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, alice.pollReceivedMessage().getContent());

        alice.send(bob.getAccount(), msg = "Oh, is that all?");
        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob.pollReceivedMessage().getContent());

        bob.send(
                alice.getAccount(),
                msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
        assertThat("Message has been transferred unencrypted.", bob
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, alice.pollReceivedMessage().getContent());

        alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob.pollReceivedMessage().getContent());

        bob.exit();
        alice.exit();
    }

    @Test
    public void testForcedStart() throws Exception {
        DummyClient[] convo = DummyClient.getConversation();
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];

        DummyClient.forceStartOtr(alice, bob);
        assertEquals("The session is not encrypted.", SessionStatus.ENCRYPTED,
                bob.getSession().getSessionStatus());
        assertEquals("The session is not encrypted.", SessionStatus.ENCRYPTED,
                alice.getSession().getSessionStatus());

        String msg;

        alice.send(
                bob.getAccount(),
                msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob.pollReceivedMessage().getContent());

        bob.send(alice.getAccount(),
                msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
        assertThat("Message has been transferred unencrypted.", bob
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, alice.pollReceivedMessage().getContent());

        alice.send(bob.getAccount(), msg = "Oh, is that all?");
        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob.pollReceivedMessage().getContent());

        bob.send(
                alice.getAccount(),
                msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
        assertThat("Message has been transferred unencrypted.", bob
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, alice.pollReceivedMessage().getContent());

        alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
        assertThat("Message has been transferred unencrypted.", alice
                .getConnection().getSentMessage(), not(equalTo(msg)));

        assertEquals("Received message is different from the sent message.",
                msg, bob.pollReceivedMessage().getContent());

        bob.exit();
        alice.exit();
    }

    @Test
    public void testPlaintext() throws Exception {
        DummyClient[] convo = DummyClient.getConversation();
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];

        String msg;

        alice.send(bob.getAccount(),
                msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

        ProcessedTestMessage pMsg = bob.pollReceivedMessage();

        assertEquals("The session is not encrypted.", SessionStatus.PLAINTEXT,
                bob.getSession().getSessionStatus());
        assertEquals("The session is not encrypted.", SessionStatus.PLAINTEXT,
                alice.getSession().getSessionStatus());

        assertEquals("Message has been altered (but it shouldn't).", msg, alice
                .getConnection().getSentMessage());

        assertEquals("Received message is different from the sent message.",
                msg, pMsg.getContent());

        bob.send(alice.getAccount(),
                msg = "Hey Alice, it means that our communication is encrypted and authenticated.");

        assertEquals("Message has been altered (but it shouldn't).", msg, bob
                .getConnection().getSentMessage());

        pMsg = alice.pollReceivedMessage();
        assertEquals("Received message is different from the sent message.",
                msg, pMsg.getContent());

        alice.send(bob.getAccount(), msg = "Oh, is that all?");

        assertEquals("Message has been altered (but it shouldn't).", msg, alice
                .getConnection().getSentMessage());

        assertEquals("Received message is different from the sent message.",
                msg, bob.pollReceivedMessage().getContent());

        bob.send(alice.getAccount(),
                msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");

        assertEquals("Message has been altered (but it shouldn't).", msg, bob
                .getConnection().getSentMessage());

        pMsg = alice.pollReceivedMessage();
        assertEquals("Received message is different from the sent message.",
                msg, pMsg.getContent());

        alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");

        assertEquals("Message has been altered (but it shouldn't).", msg, alice
                .getConnection().getSentMessage());

        pMsg = bob.pollReceivedMessage();
        assertEquals("Received message is different from the sent message.",
                msg, pMsg.getContent());

        bob.exit();
        alice.exit();
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
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        assertNull(c.clientBob.receiveMessage());
        c.clientAlice.session.endSession();
        assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertNull(c.clientBob.receiveMessage());
        assertEquals(SessionStatus.FINISHED, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionFragmented() throws OtrException {
        final Conversation c = new Conversation(150, 20);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
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
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
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
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
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
        final Conversation c = new Conversation(150, 20);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
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
        final Conversation c = new Conversation(150, 20);
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
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        shuffle(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
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
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
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

        private final Client clientAlice;
        private final Client clientBob;

        /**
         * Constructor with defaults: Unlimited-length messages.
         *
         * @param channelCapacity Maximum number of messages allowed to be in transit simultaneously.
         */
        private Conversation(final int channelCapacity) {
            final LinkedBlockingQueue<String> directChannelAlice = new LinkedBlockingQueue<>(channelCapacity);
            final BlockingSubmitter<String> channelAlice = new BlockingSubmitter<>(
                Collections.<BlockingQueue<String>>singleton(directChannelAlice));
            final LinkedBlockingQueue<String> directChannelBob = new LinkedBlockingQueue<>(channelCapacity);
            final BlockingSubmitter<String> channelBob = new BlockingSubmitter<>(
                Collections.<BlockingQueue<String>>singleton(directChannelBob));
            final SessionID sessionIDBob = new SessionID("bob@InMemoryNetwork4", "alice@InMemoryNetwork4",
                "InMemoryNetwork4");
            final SessionID sessionIDAlice = new SessionID("alice@InMemoryNetwork4", "bob@InMemoryNetwork4",
                "InMemoryNetwork4");
            this.clientBob = new Client("Bob", sessionIDBob, new OtrPolicy(OtrPolicy.OTRL_POLICY_MANUAL), RANDOM,
                channelAlice, directChannelBob);
            this.clientAlice = new Client("Alice", sessionIDAlice, new OtrPolicy(OtrPolicy.OTRL_POLICY_MANUAL),
                RANDOM, channelBob, directChannelAlice);
        }

        /**
         * Constructor with configurable maximum message size and channel capacity (maximum number of messages
         * simultaneously stored).
         *
         * @param maxMessageSize  Maximum size of message allowed.
         * @param channelCapacity Maximum number of messages allowed to be in transit simultaneously.
         */
        private Conversation(final int maxMessageSize, final int channelCapacity) {
            final Predicate<String> condition = new MaxMessageSize(maxMessageSize);
            final ConditionalBlockingQueue<String> directChannelAlice = new ConditionalBlockingQueue<>(
                new LinkedBlockingQueue<String>(channelCapacity), condition);
            final BlockingSubmitter<String> channelAlice = new BlockingSubmitter<>(
                Collections.<BlockingQueue<String>>singleton(directChannelAlice));
            final ConditionalBlockingQueue<String> directChannelBob = new ConditionalBlockingQueue<>(
                new LinkedBlockingQueue<String>(channelCapacity), condition);
            final BlockingSubmitter<String> channelBob = new BlockingSubmitter<>(
                Collections.<BlockingQueue<String>>singleton(directChannelBob));
            final SessionID sessionIDBob = new SessionID("bob@InMemoryNetwork4", "alice@InMemoryNetwork4",
                "InMemoryNetwork4");
            final SessionID sessionIDAlice = new SessionID("alice@InMemoryNetwork4", "bob@InMemoryNetwork4",
                "InMemoryNetwork4");
            this.clientBob = new Client("Bob", sessionIDBob, new OtrPolicy(OtrPolicy.OTRL_POLICY_MANUAL), RANDOM,
                channelAlice, directChannelBob);
            this.clientBob.setMessageSize(maxMessageSize);
            this.clientAlice = new Client("Alice", sessionIDAlice, new OtrPolicy(OtrPolicy.OTRL_POLICY_MANUAL),
                RANDOM, channelBob, directChannelAlice);
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

        private final OtrPolicy policy;

        private final ClientProfilePayload profilePayload;

        private final Session session;

        private int messageSize = Integer.MAX_VALUE;

        private Client(@Nonnull final String label, @Nonnull final SessionID sessionID, @Nonnull final OtrPolicy policy,
                       @Nonnull final SecureRandom random, @Nonnull final BlockingSubmitter<String> sendChannel,
                       @Nonnull final BlockingQueue<String> receiptChannel) {
            this.logger = Logger.getLogger(Client.class.getName() + ":" + label);
            this.ed448KeyPair = EdDSAKeyPair.generate(random);
            this.dsaKeyPair = OtrCryptoEngine.generateDSAKeyPair();
            this.receiptChannel = requireNonNull(receiptChannel);
            this.sendChannel = requireNonNull(sendChannel);
            this.policy = requireNonNull(policy);
            final Calendar expirationCalendar = Calendar.getInstance();
            expirationCalendar.add(Calendar.DAY_OF_YEAR, 7);
            final InstanceTag senderInstanceTag = InstanceTag.random(random);
            final ClientProfile profile = new ClientProfile(senderInstanceTag, this.ed448KeyPair.getPublicKey(),
                Collections.singleton(Session.OTRv.FOUR), expirationCalendar.getTimeInMillis() / 1000, null);
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
