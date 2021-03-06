/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SmpEngineHost;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.session.api.SMPHandler;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.SmpEngineHosts.askForSecret;
import static net.java.otr4j.api.SmpEngineHosts.smpAborted;
import static net.java.otr4j.api.SmpEngineHosts.unverify;
import static net.java.otr4j.api.SmpEngineHosts.verify;
import static net.java.otr4j.api.TLV.EMPTY_BODY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_SECRET;
import static net.java.otr4j.crypto.OtrCryptoEngine4.fingerprint;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.session.api.SMPStatus.FAILED;
import static net.java.otr4j.session.api.SMPStatus.SUCCEEDED;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP1;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP2;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP3;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP4;
import static net.java.otr4j.session.smpv4.SMPMessage.SMP_ABORT;
import static net.java.otr4j.session.smpv4.SMPMessages.parse;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.toHexString;
import static org.bouncycastle.util.Arrays.clear;

/**
 * OTRv4 variant of the Socialist Millionaire's Protocol.
 */
public final class SMP implements AutoCloseable, SMPContext, SMPHandler {

    private static final Logger LOGGER = Logger.getLogger(SMP.class.getName());

    private static final int SMP_SECRET_LENGTH_BYTES = 64;

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
     * @param host                   SMP engine host instance, used for interaction with the host application
     * @param sessionID              the session ID
     * @param ssid                   the ssid for the established encrypted session
     * @param ourLongTermPublicKey   local user's long-term public key
     * @param theirLongTermPublicKey the remote party's long-term public key
     * @param receiverTag            receiver tag this SMP instance belongs to
     */
    public SMP(@Nonnull final SecureRandom random, @Nonnull final SmpEngineHost host, @Nonnull final SessionID sessionID,
            @Nonnull final byte[] ssid, @Nonnull final Point ourLongTermPublicKey,
            @Nonnull final Point theirLongTermPublicKey, @Nonnull final InstanceTag receiverTag) {
        this.random = requireNonNull(random);
        this.host = requireNonNull(host);
        this.sessionID = requireNonNull(sessionID);
        this.ssid = requireNonNull(ssid);
        assert !allZeroBytes(ssid) : "Expected SSID to contain non-zero bytes. All-zero SSID is a highly unlikely situation.";
        this.receiverTag = requireNonNull(receiverTag);
        this.ourLongTermPublicKey = requireNonNull(ourLongTermPublicKey);
        this.theirLongTermPublicKey = requireNonNull(theirLongTermPublicKey);
        this.state = new StateExpect1(random, UNDECIDED);
    }

    /**
     * Check if TLV is relevant to SMP.
     *
     * @param tlv TLV to inspect
     * @return Returns true iff TLV contains SMP payload.
     */
    public static boolean smpPayload(@Nonnull final TLV tlv) {
        return tlv.type == SMP1 || tlv.type == SMP2 || tlv.type == SMP3 || tlv.type == SMP4 || tlv.type == SMP_ABORT;
    }

    @Override
    public void close() {
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
     * Initiate a new SMP negotiation.
     *
     * @param question the question
     * @param answer   the secret, i.e. the answer to the posed question
     * @return Returns an OtrEncodable to be sent to the other party.
     */
    @Nonnull
    @Override
    public TLV initiate(@Nonnull final String question, @Nonnull final byte[] answer) {
        try {
            final Scalar secret = generateSecret(answer, this.ourLongTermPublicKey, this.theirLongTermPublicKey);
            final SMPMessage1 response = this.state.initiate(this, question, secret);
            return new TLV(SMP1, encode(response));
        } catch (final SMPAbortException e) {
            return new TLV(SMP_ABORT, EMPTY_BODY);
        }
    }

    /**
     * Respond to SMP negotiation initiated by other party with provided secret.
     *
     * @param question the original question posed (used to distinguish multiple requests)
     * @param answer   the secret answer to the question
     * @return Returns TLV with response to be sent to the other party.
     */
    @Nullable
    @Override
    public TLV respond(@Nonnull final String question, @Nonnull final byte[] answer) {
        final Scalar secret = generateSecret(answer, this.theirLongTermPublicKey, this.ourLongTermPublicKey);
        final SMPMessage2 response = this.state.respondWithSecret(this, question, secret);
        if (response == null) {
            // TODO decide if we want to throw an exception or silently ignore bad (or badly timed) SMP init responses.
            return null;
        }
        return new TLV(SMP2, encode(response));
    }

    private Scalar generateSecret(@Nonnull final byte[] answer, @Nonnull final Point initiatorPublicKey,
            @Nonnull final Point responderPublicKey) {
        final byte[] secretInputData = new OtrOutputStream().writeByte(VERSION)
                .writeFingerprint(fingerprint(initiatorPublicKey))
                .writeFingerprint(fingerprint(responderPublicKey))
                .writeSSID(this.ssid).writeData(answer).toByteArray();
        return decodeScalar(kdf1(SMP_SECRET, secretInputData, SMP_SECRET_LENGTH_BYTES));
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return this.state.getStatus();
    }

    /**
     * Process an SMP TLV payload.
     *
     * @param tlv the SMP tlv
     * @return Returns an OtrEncodable with the response to SMP message 1.
     * @throws ProtocolException  In case of failure parsing SMP messages.
     * @throws OtrCryptoException In case of failure in cryptographic parts of SMP messages.
     */
    @Nullable
    public TLV process(@Nonnull final TLV tlv) throws ProtocolException, OtrCryptoException {
        if (tlv.type == SMP_ABORT) {
            abort();
            return null;
        }
        final SMPMessage response;
        try {
            response = this.state.process(this, parse(tlv));
        } catch (final SMPAbortException e) {
            setState(new StateExpect1(this.random, UNDECIDED));
            smpAborted(this.host, this.sessionID);
            return new TLV(SMP_ABORT, new byte[0]);
        }
        if (this.state.getStatus() == SUCCEEDED) {
            verify(this.host, this.sessionID, toHexString(fingerprint(this.theirLongTermPublicKey)));
        } else if (this.state.getStatus() == FAILED) {
            unverify(this.host, this.sessionID, toHexString(fingerprint(this.theirLongTermPublicKey)));
        }
        if (response == null) {
            return null;
        } else if (response instanceof SMPMessage3) {
            return new TLV(SMP3, encode(response));
        } else if (response instanceof SMPMessage4) {
            return new TLV(SMP4, encode(response));
        }
        throw new IllegalStateException("Unexpected SMP response type: " + response.getClass() + ". Cannot construct corresponding TLV.");
    }

    /**
     * Abort an in-progress SMP negotiation.
     */
    @Nonnull
    @Override
    public TLV abort() {
        // TODO consider not doing an unconditional state change, but instead check if "abort" has impact. (see OTRv3 implementation)
        setState(new StateExpect1(this.random, UNDECIDED));
        smpAborted(this.host, this.sessionID);
        return new TLV(SMP_ABORT, EMPTY_BODY);
    }

    @Override
    public boolean smpAbortedTLV(@Nonnull final TLV tlv) {
        return tlv.type == SMP_ABORT;
    }
}
