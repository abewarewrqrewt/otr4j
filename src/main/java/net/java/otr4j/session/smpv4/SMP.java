package net.java.otr4j.session.smpv4;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SmpEngineHost;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrOutputStream;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.SmpEngineHostUtil.askForSecret;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_SECRET;
import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.session.smpv4.SMPMessages.parse;
import static net.java.otr4j.session.smpv4.SMPStatus.UNDECIDED;
import static org.bouncycastle.util.Arrays.clear;

/**
 * OTRv4 variant of the Socialist Millionaire's Protocol.
 */
public final class SMP implements AutoCloseable, SMPContext {

    private static final Logger LOGGER = Logger.getLogger(SMP.class.getName());

    private static final byte VERSION = 1;

    private final SecureRandom random;

    private final SmpEngineHost host;

    private final byte[] ssid;

    private final SessionID sessionID;

    private final InstanceTag receiverTag;

    private final Point ourLongTermPublicKey;

    private final Point theirLongTermPublicKey;

    private SMPState state;

    /**
     * Constructor for SMP implementation.
     *
     * @param random                 SecureRandom instance
     * @param host                   SMP engine host
     * @param sessionID              the session ID
     * @param ssid                   the ssid for the established encrypted session
     * @param ourLongTermPublicKey   local user's long-term public key
     * @param theirLongTermPublicKey the remote party's long-term public key
     * @param receiverTag            receiver tag this SMP instance maintains
     */
    public SMP(@Nonnull final SecureRandom random, @Nonnull final SmpEngineHost host, @Nonnull final SessionID sessionID,
            @Nonnull final byte[] ssid, @Nonnull final Point ourLongTermPublicKey,
            @Nonnull final Point theirLongTermPublicKey, @Nonnull final InstanceTag receiverTag) {
        this.random = requireNonNull(random);
        this.host = requireNonNull(host);
        this.sessionID = requireNonNull(sessionID);
        this.ssid = requireNonNull(ssid);
        this.receiverTag = requireNonNull(receiverTag);
        this.ourLongTermPublicKey = requireNonNull(ourLongTermPublicKey);
        this.theirLongTermPublicKey = requireNonNull(theirLongTermPublicKey);
        this.state = new StateExpect1(random, UNDECIDED);
    }

    @Override
    public void close() {
        // FIXME investigate what else needs to be cleared at resource clean-up.
        clear(this.ssid);
    }

    @Override
    public void setState(@Nonnull final SMPState newState) {
        this.state = requireNonNull(newState);
        LOGGER.log(Level.FINE, "SMP transitioning to state {0}", newState);
    }

    @Override
    public void requestSecret(@Nonnull final String question) {
        askForSecret(this.host, this.sessionID, this.receiverTag, question);
    }

    /**
     * Get the current SMP state machine status.
     *
     * @return Returns the status.
     */
    public SMPStatus getStatus() {
        return this.state.getStatus();
    }

    /**
     * Initiate a new SMP negotiation.
     *
     * @param question the question
     * @param answer   the secret, i.e. the answer to the posed question
     * @return Returns an OtrEncodable to be sent to the other party.
     */
    @Nonnull
    public TLV initiate(@Nonnull final String question, @Nonnull final byte[] answer) {
        final BigInteger secret = generateSecret(answer, this.ourLongTermPublicKey, this.theirLongTermPublicKey);
        final SMPMessage1 response = this.state.initiate(this, question, secret);
        return new TLV(TLV.SMP1, encode(response));
    }

    /**
     * Respond to SMP negotiation initiated by other party with provided secret.
     *
     * @param question the original question posed (used to distinguish multiple requests)
     * @param answer   the secret answer to the question
     * @return Returns TLV with response to be sent to the other party.
     */
    public TLV respondWithSecret(@Nonnull final String question, @Nonnull final byte[] answer) {
        final BigInteger secret = generateSecret(answer, this.theirLongTermPublicKey, this.ourLongTermPublicKey);
        final SMPMessage2 response = this.state.respondWithSecret(this, question, secret);
        if (response == null) {
            return null;
        }
        return new TLV(TLV.SMP2, encode(response));
    }

    private BigInteger generateSecret(@Nonnull final byte[] answer, @Nonnull final Point initiatorPublicKey,
            @Nonnull final Point responderPublicKey) {
        final byte[] secretInputData = new OtrOutputStream().writeByte(VERSION)
                .writeFingerprint(fingerprint(initiatorPublicKey))
                .writeFingerprint(fingerprint(responderPublicKey))
                .writeSSID(this.ssid).writeData(answer).toByteArray();
        // FIXME use hashToScalar or KDF1 with interpretation as unsigned little endian (or something else) afterwards? (https://github.com/otrv4/otrv4/issues/172)
        return hashToScalar(SMP_SECRET, secretInputData);
    }

    /**
     * Process an SMP TLV payload.
     *
     * @param tlv the SMP tlv
     * @return Returns an OtrEncodable with the response to SMP message 1.
     * @throws ProtocolException  In case of failure parsing SMP messages.
     * @throws OtrCryptoException In case of failure to cryptographic parts of SMP messages.
     */
    @Nullable
    public TLV process(@Nonnull final TLV tlv) throws ProtocolException, OtrCryptoException {
        final SMPMessage response;
        try {
            response = this.state.process(this, parse(tlv));
            if (response == null) {
                return null;
            }
        } catch (final SMPAbortException e) {
            setState(new StateExpect1(this.random, UNDECIDED));
            return new TLV(TLV.SMP_ABORT, new byte[0]);
        }
        if (response instanceof SMPMessage1) {
            return new TLV(TLV.SMP1, encode(response));
        } else if (response instanceof SMPMessage2) {
            return new TLV(TLV.SMP2, encode(response));
        } else if (response instanceof SMPMessage3) {
            return new TLV(TLV.SMP3, encode(response));
        } else if (response instanceof SMPMessage4) {
            return new TLV(TLV.SMP4, encode(response));
        }
        throw new IllegalStateException("Unknown SMP response type: " + response.getClass() + ". Cannot construct corresponding TLV.");
    }

    /**
     * Abort an in-progress SMP negotiation.
     */
    public void abort() {
        setState(new StateExpect1(this.random, UNDECIDED));
    }
}
