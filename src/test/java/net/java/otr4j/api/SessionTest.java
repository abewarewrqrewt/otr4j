
package net.java.otr4j.api;

import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.messages.ClientProfilePayload;
import net.java.otr4j.profile.ClientProfile;
import net.java.otr4j.test.TestStrings;
import net.java.otr4j.test.dummyclient.DummyClient;
import net.java.otr4j.test.dummyclient.PriorityServer;
import net.java.otr4j.test.dummyclient.ProcessedTestMessage;
import net.java.otr4j.test.dummyclient.Server;
import org.junit.Before;
import org.junit.Test;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.Integer.MAX_VALUE;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.session.OtrSessionManager.createSession;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

public class SessionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Before
    public void setUp() {
        Logger.getLogger("").setLevel(Level.ALL);
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
    public void testPlainTextMessagingNewClients() throws OtrException, InterruptedException {
        final Conversation c = new Conversation();
        c.hostBob.sendMessage("hello world");
        assertEquals("hello world", c.hostAlice.receiveMessage());
        c.hostAlice.sendMessage("hello bob");
        assertEquals("hello bob", c.hostBob.receiveMessage());
    }

    @Test
    public void testEstablishOTR4Session() throws OtrException {
        final Conversation c = new Conversation();
        c.hostBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.hostAlice.receiveMessage());
        c.hostAlice.sendRequest();
        assertNull(c.hostBob.receiveMessage());
        assertNull(c.hostAlice.receiveMessage());
        assertNull(c.hostBob.receiveMessage());
        assertEquals(SessionStatus.ENCRYPTED, c.hostBob.getMessageState());
        assertNull(c.hostAlice.receiveMessage());
        assertEquals(SessionStatus.ENCRYPTED, c.hostAlice.getMessageState());
        // FIXME extend test with final receive such that we are sure that both DoubleRatchets are fully initialized.
    }

    /**
     * Dummy conversation implementation, mimicking a conversation between two parties.
     */
    private static final class Conversation {

        private final Client hostAlice;
        private final Client hostBob;

        private Conversation() {
            final LinkedBlockingQueue<String> channelAlice = new LinkedBlockingQueue<>(1);
            final LinkedBlockingQueue<String> channelBob = new LinkedBlockingQueue<>(1);
            final SessionID sessionIDBob = new SessionID("bob@DummyNetwork4", "alice@DummyNetwork4",
                "DummyNetwork4");
            final SessionID sessionIDAlice = new SessionID("alice@DummyNetwork4", "bob@DummyNetwork4",
                "DummyNetwork4");
            this.hostBob = new Client("Bob", sessionIDBob, new OtrPolicy(OtrPolicy.OTRL_POLICY_MANUAL), RANDOM,
                channelAlice, channelBob);
            this.hostAlice = new Client("Alice", sessionIDAlice, new OtrPolicy(OtrPolicy.OTRL_POLICY_MANUAL),
                RANDOM, channelBob, channelAlice);
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

        private final BlockingQueue<String> sendChannel;

        private final BlockingQueue<String> receiptChannel;

        private final OtrPolicy policy;

        private final ClientProfilePayload profilePayload;

        private final Session session;

        private Client(@Nonnull final String label, @Nonnull final SessionID sessionID, @Nonnull final OtrPolicy policy,
                       @Nonnull final SecureRandom random, @Nonnull final BlockingQueue<String> sendChannel,
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
            final ClientProfile profile = new ClientProfile(senderInstanceTag.getValue(),
                this.ed448KeyPair.getPublicKey(), Collections.singleton(Session.OTRv.FOUR),
                expirationCalendar.getTimeInMillis() / 1000, null);
            this.profilePayload = ClientProfilePayload.sign(profile, null, this.ed448KeyPair);
            this.session = createSession(sessionID, this, senderInstanceTag);
        }

        public String receiveMessage() throws OtrException {
            final String msg = this.receiptChannel.remove();
            return this.session.transformReceiving(msg);
        }

        public void sendMessage(@Nonnull final String msg) throws OtrException {
            this.sendChannel.addAll(Arrays.asList(this.session.transformSending(msg)));
        }

        public void sendRequest() throws OtrException {
            this.session.startSession();
        }

        @Nonnull
        public SessionStatus getMessageState() {
            return this.session.getSessionStatus();
        }

        @Override
        public void injectMessage(@Nonnull final SessionID sessionID, @Nonnull final String msg) {
            try {
                this.sendChannel.put(msg);
            } catch (final InterruptedException e) {
                throw new IllegalStateException("Failed to inject message into simulated chat receiptChannel.", e);
            }
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
            return MAX_VALUE;
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
            return OtrCryptoEngine.getFingerprintRaw(this.dsaKeyPair.getPublic());
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
