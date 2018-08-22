/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smp;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SmpEngineHost;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.session.api.SMPHandler;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.SmpEngineHostUtil.askForSecret;
import static net.java.otr4j.api.SmpEngineHostUtil.smpAborted;
import static net.java.otr4j.api.SmpEngineHostUtil.smpError;
import static net.java.otr4j.api.SmpEngineHostUtil.unverify;
import static net.java.otr4j.api.SmpEngineHostUtil.verify;
import static net.java.otr4j.crypto.OtrCryptoEngine.getFingerprintRaw;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha256Hash;
import static net.java.otr4j.session.api.SMPStatus.CHEATED;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.api.SMPStatus.SUCCEEDED;

/**
 * SMP TLV Handler handles any interaction w.r.t. mutual authentication using
 * SMP (Socialist Millionaires Protocol).
 *
 * @author Danny van Heumen
 */
public final class SmpTlvHandler implements SMPHandler {

    private static final byte[] VERSION_BYTE = new byte[] {1};

    private final SmpEngineHost host;
    private final SessionID sessionID;
    private final DSAPublicKey remotePublicKey;
    private final SharedSecret s;
    private final SM sm;
    private final InstanceTag receiverTag;

    /**
     * Construct an OTR Socialist Millionaire handler object.
     *
     * @param random          SecureRandom instance
     * @param sessionID       session ID
     * @param remotePublicKey the remote public key
     * @param receiverTag     the receiver instance tag for this SMP session
     * @param host            the SMP engine host
     * @param s               the session's shared secret
     */
    public SmpTlvHandler(@Nonnull final SecureRandom random, @Nonnull final SessionID sessionID,
            @Nonnull final DSAPublicKey remotePublicKey, @Nonnull final InstanceTag receiverTag,
            @Nonnull final SmpEngineHost host, @Nonnull final SharedSecret s) {
        this.sessionID = requireNonNull(sessionID);
        this.remotePublicKey = requireNonNull(remotePublicKey);
        this.s = requireNonNull(s);
        this.host = requireNonNull(host);
        this.sm = new SM(random);
        this.receiverTag = requireNonNull(receiverTag);
    }

    @Nonnull
    @Override
    public TLV initiate(@Nonnull final String question, @Nonnull final byte[] answer) throws OtrException {
        try {
            return initRespondSmp(question, answer, true);
        } catch (final SMException e) {
            throw new OtrException("Failed to initiate SMP negotiation.", e);
        }
    }

    @Nonnull
    @Override
    public TLV respond(@Nonnull final String question, @Nonnull final byte[] answer) throws OtrException {
        try {
            return initRespondSmp(question, answer, false);
        } catch (final SMException e) {
            throw new OtrException("Failed to respond to SMP with answer to the question.", e);
        }
    }

    /**
     * Respond to or initiate an SMP negotiation
     *
     * @param question   The question to present to the peer, if initiating.
     *                   May be <code>null</code> for no question.
     *                   If not initiating, then it should be received question
     *                   in order to clarify whether this is shared secret verification.
     * @param answer     The secret.
     * @param initiating Whether we are initiating or responding to an initial request.
     * @return TLVs to send to the peer
     * @throws OtrException Failures in case an SMP step cannot be processed
     *                      successfully, or in case expected data is not provided.
     * @throws SMException  In case of failure while processing SMP TLV record.
     */
    @Nonnull
    private TLV initRespondSmp(@Nonnull final String question, @Nonnull final byte[] answer, final boolean initiating)
            throws OtrException, SMException {
        if (!initiating && this.sm.status() != INPROGRESS) {
            throw new OtrException("There is no question to be answered.");
        }
        final byte[] initiatorFingerprint;
        final byte[] responderFingerprint;
        if (initiating) {
            initiatorFingerprint = this.host.getLocalFingerprintRaw(this.sessionID);
            responderFingerprint = getFingerprintRaw(this.remotePublicKey);
        } else {
            initiatorFingerprint = getFingerprintRaw(this.remotePublicKey);
            responderFingerprint = this.host.getLocalFingerprintRaw(this.sessionID);
        }
        final byte[] secret = generateSecret(answer, initiatorFingerprint, responderFingerprint);

        byte[] smpmsg;
        try {
            smpmsg = initiating ? sm.step1(secret) : sm.step2b(secret);
        } catch (final SMAbortedException e) {
            // As prescribed by OTR, we must always be allowed to initiate a new SMP exchange. In case another SMP
            // exchange is in progress, an abort is signaled. We honor the abort exception and send the abort signal
            // to the counter party. Then we immediately initiate a new SMP exchange as requested.
            smpAborted(this.host, this.sessionID);
            return new TLV(TLV.SMP_ABORT, TLV.EMPTY_BODY);
        }

        // If we've got a question, attach it to the smpmsg
        if (!question.isEmpty() && initiating) {
            final byte[] questionBytes = question.getBytes(UTF_8);
            final byte[] qsmpmsg = new byte[questionBytes.length + 1 + smpmsg.length];
            System.arraycopy(questionBytes, 0, qsmpmsg, 0, questionBytes.length);
            System.arraycopy(smpmsg, 0, qsmpmsg, questionBytes.length + 1, smpmsg.length);
            smpmsg = qsmpmsg;
        }

        return new TLV(initiating ? question.isEmpty() ? TLV.SMP1 : TLV.SMP1Q : TLV.SMP2, smpmsg);
    }

    /**
     * Construct the combined secret as a SHA-256 hash of:
     * <ol>
     * <li>Version byte (0x01)</li>
     * <li>Initiator fingerprint</li>
     * <li>Responder fingerprint</li>
     * <li>Secure session id a.k.a. SSID</li>
     * <li>secret answer</li>
     * </ol>
     *
     * @param answer the answer of the local user
     * @return Returns the generated secret MPI to be used in SMP.
     */
    private byte[] generateSecret(@Nonnull final byte[] answer, @Nonnull final byte[] initiatorFingerprint,
            @Nonnull final byte[] responderFingerprint) {
        return sha256Hash(VERSION_BYTE, initiatorFingerprint, responderFingerprint, this.s.ssid(), answer);
    }

    @Nonnull
    @Override
    public TLV abort() {
        if (this.sm.abort()) {
            smpAborted(host, this.sessionID);
        }
        return new TLV(TLV.SMP_ABORT, TLV.EMPTY_BODY);
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return this.sm.status();
    }

    /**
     * Process TLV payload intended for SMP.
     *
     * @param tlv the payload
     * @return Returns response to provided payload.
     * @throws SMException In case of failure to process TLV.
     */
    @Nullable
    public TLV process(@Nonnull final TLV tlv) throws SMException {
        try {
            switch (tlv.getType()) {
            case TLV.SMP1:
                return processTlvSMP1(tlv);
            case TLV.SMP1Q:
                return processTlvSMP1Q(tlv);
            case TLV.SMP2:
                return processTlvSMP2(tlv);
            case TLV.SMP3:
                return processTlvSMP3(tlv);
            case TLV.SMP4:
                return processTlvSMP4(tlv);
            default:
                throw new IllegalStateException("Unknown SMP TLV type: " + tlv.getType() + ". Cannot process this TLV.");
            }
        } catch (final SMAbortedException e) {
            smpAborted(this.host, this.sessionID);
            return new TLV(TLV.SMP_ABORT, TLV.EMPTY_BODY);
        } catch (final SMException e) {
            smpError(this.host, this.sessionID, tlv.getType(), this.sm.status() == CHEATED);
            throw e;
        }
    }

    @Nullable
    private TLV processTlvSMP1Q(@Nonnull final TLV tlv) throws SMException {
        // We can only do the verification half now.
        // We must wait for the secret to be entered
        // to continue.
        final byte[] question = tlv.getValue();
        int qlen = 0;
        while (qlen != question.length && question[qlen] != 0) {
            qlen++;
        }
        if (qlen == question.length) {
            qlen = 0;
        } else {
            qlen++;
        }
        final byte[] input = new byte[question.length - qlen];
        System.arraycopy(question, qlen, input, 0, question.length - qlen);
        sm.step2a(input);
        if (qlen != 0) {
            qlen--;
        }
        final byte[] plainq = new byte[qlen];
        System.arraycopy(question, 0, plainq, 0, qlen);
        askForSecret(host, this.sessionID, this.receiverTag, new String(plainq, UTF_8));
        return null;
    }

    @Nullable
    private TLV processTlvSMP1(@Nonnull final TLV tlv) throws SMException {
        // We can only do the verification half now. We must wait for the secret to be entered to continue.
        sm.step2a(tlv.getValue());
        askForSecret(host, this.sessionID, this.receiverTag, null);
        return null;
    }

    @Nonnull
    private TLV processTlvSMP2(@Nonnull final TLV tlv) throws SMException {
        final byte[] nextmsg = sm.step3(tlv.getValue());
        return new TLV(TLV.SMP3, nextmsg);
    }

    @Nonnull
    private TLV processTlvSMP3(@Nonnull final TLV tlv) throws SMException {
        final byte[] nextmsg = sm.step4(tlv.getValue());
        // Set trust level based on result.
        if (this.sm.status() == SUCCEEDED) {
            verify(host, this.sessionID, getFingerprint());
        } else {
            unverify(host, this.sessionID, getFingerprint());
        }
        return new TLV(TLV.SMP4, nextmsg);
    }

    @Nullable
    private TLV processTlvSMP4(@Nonnull final TLV tlv) throws SMException {
        sm.step5(tlv.getValue());
        if (this.sm.status() == SUCCEEDED) {
            verify(host, this.sessionID, getFingerprint());
        } else {
            unverify(host, this.sessionID, getFingerprint());
        }
        return null;
    }

    @Nonnull
    private String getFingerprint() {
        return OtrCryptoEngine.getFingerprint(this.remotePublicKey);
    }
}
