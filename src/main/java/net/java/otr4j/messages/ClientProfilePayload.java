/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.DSAKeyPair.DSASignature;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.UnsupportedTypeException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.InstanceTag.isValidInstanceTag;
import static net.java.otr4j.crypto.DSAKeyPair.verifySignature;
import static net.java.otr4j.crypto.OtrCryptoEngine4.verifyEdDSAPublicKey;
import static net.java.otr4j.io.MessageParser.encodeVersionString;
import static net.java.otr4j.io.MessageParser.parseVersionString;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.Iterables.findByType;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * The client profile payload.
 * <p>
 * This is the client profile in a representation that is easily serializable and that is able to carry the signatures
 * corresponding to the client profile.
 * <p>
 * The client profile payload is the unverified container for the data received from other parties. {@link #validate()}
 * will validate on success convert the type to the actual {@link ClientProfile} data-type. This split ensures that
 * client profiles are validated before trusted use.
 */
@SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
public final class ClientProfilePayload implements OtrEncodable {

    private static final Logger LOGGER = Logger.getLogger(ClientProfilePayload.class.getName());

    private final List<Field> fields;

    private final byte[] signature;

    /**
     * Constructor for payload remains private as we expect to create this only from one of 2 sources:
     * 1. A ClientProfile instances to be converted.
     * 2. An (untrusted) input source to be deserialized.
     *
     * @param fields    The fields that are part of the payload.
     * @param signature The signature by the long-term public key.
     */
    @SuppressWarnings("PMD.ArrayIsStoredDirectly")
    private ClientProfilePayload(@Nonnull final List<Field> fields, @Nonnull final byte[] signature) {
        this.fields = requireNonNull(fields);
        this.signature = requireNonNull(signature);
    }

    /**
     * Generates a client profile payload by converting the profile and signing with provided keys.
     *
     * @param profile       The client profile to be converted.
     * @param dsaPrivateKey OTRv3 DSA private key for signing. (Transitional signature)
     * @param eddsaKeyPair  EdDSA key pair.
     * @return Returns a Client Profile payload that can be serialized to an OTR-encoded data stream.
     */
    @Nonnull
    public static ClientProfilePayload sign(@Nonnull final ClientProfile profile,
            @Nullable final DSAKeyPair dsaPrivateKey, @Nonnull final EdDSAKeyPair eddsaKeyPair) {
        final ArrayList<Field> fields = new ArrayList<>();
        fields.add(new InstanceTagField(profile.getInstanceTag().getValue()));
        fields.add(new ED448PublicKeyField(profile.getLongTermPublicKey()));
        fields.add(new ED448ForgingKeyField(profile.getForgingKey()));
        fields.add(new VersionsField(profile.getVersions()));
        fields.add(new ExpirationDateField(profile.getExpirationUnixTime()));
        final DSAPublicKey dsaPublicKey = profile.getDsaPublicKey();
        if (dsaPublicKey != null) {
            if (dsaPrivateKey == null) {
                throw new IllegalArgumentException("DSA public key provided, but private key is not provided.");
            }
            fields.add(new DSAPublicKeyField(dsaPublicKey));
        }
        final OtrOutputStream out = new OtrOutputStream();
        for (final Field field : fields) {
            out.write(field);
        }
        final byte[] partialM = out.toByteArray();
        final byte[] m;
        if (dsaPrivateKey == null) {
            m = partialM;
        } else {
            final DSASignature transitionalSignature = dsaPrivateKey.signRS(partialM);
            final TransitionalSignatureField sigField = new TransitionalSignatureField(transitionalSignature);
            fields.add(sigField);
            m = concatenate(partialM, encode(sigField));
        }
        final byte[] signature = eddsaKeyPair.sign(m);
        // We assume that the internally generated client profiles are correct, however it is tested when assertions are
        // enabled.
        assert testValidate(fields, signature, new Date()) : "BUG: Internally constructed client profile payload fails validation. This should not happen.";
        return new ClientProfilePayload(fields, signature);
    }

    /**
     * Read Client Profile payload from OTR-encoded input stream.
     *
     * @param in The OTR-encoded input stream.
     * @return Returns ClientProfilePayload as read from input stream.
     * @throws ProtocolException   In case of failure to read the expected data from the input stream.
     * @throws OtrCryptoException  In case of failure to restore cryptographic components in the payload.
     * @throws ValidationException In case of failure to validate the client profile after reading. This indicates that
     *                             the various fields were valid but the composition of the profile is illegal.
     */
    @Nonnull
    static ClientProfilePayload readFrom(@Nonnull final OtrInputStream in) throws OtrCryptoException, ProtocolException,
            ValidationException {
        final int numFields = in.readInt();
        if (numFields <= 0) {
            throw new ProtocolException("Invalid number of fields: " + numFields);
        }
        final ArrayList<Field> fields = new ArrayList<>();
        for (int i = 0; i < numFields; i++) {
            final FieldType type = FieldType.findType(in.readShort());
            if (type == null) {
                throw new ProtocolException("Unknown field type encountered.");
            }
            switch (type) {
            case INSTANCE_TAG:
                fields.add(new InstanceTagField(in.readInt()));
                break;
            case LONG_TERM_EDDSA_PUBLIC_KEY:
                final int publicKeyType = in.readShort();
                switch (publicKeyType) {
                case ED448PublicKeyField.ED448_PUBLIC_KEY_TYPE:
                    final Point publicKey = in.readPoint();
                    fields.add(new ED448PublicKeyField(publicKey));
                    break;
                default:
                    throw new ProtocolException("Unsupported Ed448 public key type: " + publicKeyType);
                }
                break;
            case ED448_FORGING_PUBLIC_KEY:
                final int forgingKeyType = in.readShort();
                switch (forgingKeyType) {
                case ED448ForgingKeyField.ED448_FORGING_KEY_TYPE:
                    final Point publicKey = in.readPoint();
                    fields.add(new ED448ForgingKeyField(publicKey));
                    break;
                default:
                    throw new ProtocolException("Unsupported Ed448 forging key type: " + forgingKeyType);
                }
                break;
            case VERSIONS:
                try {
                    final Set<Integer> versions = parseVersionString(new String(in.readData(), US_ASCII));
                    fields.add(new VersionsField(versions));
                } catch (final UnsupportedLengthException e) {
                    throw new ProtocolException("Versions are not expected to be stored in an exceptionally large data field. This is not according to specification.");
                }
                break;
            case PROFILE_EXPIRATION:
                fields.add(new ExpirationDateField(in.readLong()));
                break;
            case TRANSITIONAL_SIGNATURE:
                final BigInteger r = in.readBigInt();
                final BigInteger s = in.readBigInt();
                fields.add(new TransitionalSignatureField(new DSASignature(r, s)));
                break;
            case TRANSITIONAL_DSA_PUBLIC_KEY:
                try {
                    fields.add(new DSAPublicKeyField(in.readPublicKey()));
                } catch (final UnsupportedTypeException e) {
                    throw new ProtocolException("Unsupported type of OTRv3 Public Key encountered.");
                }
                break;
            default:
                throw new ProtocolException("Unknown field type encountered: " + type);
            }
        }
        final byte[] signature = in.readEdDSASignature();
        validate(fields, signature, new Date());
        return new ClientProfilePayload(fields, signature);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ClientProfilePayload that = (ClientProfilePayload) o;
        return Objects.equals(fields, that.fields) && constantTimeEquals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(fields);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public void writeTo(@Nonnull final OtrOutputStream out) {
        out.writeInt(this.fields.size());
        for (final Field field : this.fields) {
            out.write(field);
        }
        out.writeEdDSASignature(signature);
    }

    /**
     * Validate the Client Profile payload and return a corresponding Client Profile instance iff validation succeeds.
     *
     * @return Returns ClientProfile iff validation succeeds.
     * @throws ValidationException In case of validation failure.
     */
    @Nonnull
    public ClientProfile validate() throws ValidationException {
        validate(this.fields, this.signature, new Date());
        return reconstructClientProfile();
    }

    /**
     * Reconstruct client profile from fields and signatures stored in the payload.
     * <p>
     * This method is expected to succeed always. Validation MUST be performed prior to calling this method to ensure
     * that a valid composition of fields is available.
     *
     * @return Returns reconstructed client profile from fields and signatures stored inside the payload.
     */
    @Nonnull
    private ClientProfile reconstructClientProfile() {
        final InstanceTag instanceTag = new InstanceTag(findByType(this.fields, InstanceTagField.class).instanceTag);
        final Point longTermPublicKey = findByType(this.fields, ED448PublicKeyField.class).publicKey;
        final Point forgingKey = findByType(this.fields, ED448ForgingKeyField.class).publicKey;
        final Set<Integer> versions = findByType(this.fields, VersionsField.class).versions;
        final long expirationUnixTime = findByType(this.fields, ExpirationDateField.class).timestamp;
        final DSAPublicKeyField dsaPublicKeyField = findByType(this.fields, DSAPublicKeyField.class, null);
        return new ClientProfile(instanceTag, longTermPublicKey, forgingKey, versions, expirationUnixTime,
            dsaPublicKeyField == null ? null : dsaPublicKeyField.publicKey);
    }

    /**
     * Custom method to make {@link #validate()} suitable for assertions.
     *
     * @return true iff validated successfully
     */
    private static boolean testValidate(@Nonnull final List<Field> fields, @Nonnull final byte[] signature,
            @Nonnull final Date now) {
        try {
            validate(fields, signature, now);
            return true;
        } catch (final ValidationException e) {
            LOGGER.log(Level.SEVERE, "Failed validation.", e);
            return false;
        }
    }

    /**
     * Verify consistency of fields list.
     *
     * @param fields    List of fields.
     * @param signature The OTRv4 signature for the fields contained in the client profile.
     * @throws ValidationException In case ClientProfilePayload contents are not inconsistent or signature is invalid.
     */
    private static void validate(@Nonnull final List<Field> fields, @Nonnull final byte[] signature,
            @Nonnull final Date now) throws ValidationException {
        // TODO not very elegant way of implementing. This can probably be done much nicer.
        final ArrayList<InstanceTagField> instanceTagFields = new ArrayList<>();
        final ArrayList<ED448PublicKeyField> publicKeyFields = new ArrayList<>();
        final ArrayList<ED448ForgingKeyField> forgingKeyFields = new ArrayList<>();
        final ArrayList<VersionsField> versionsFields = new ArrayList<>();
        final ArrayList<ExpirationDateField> expirationDateFields = new ArrayList<>();
        final ArrayList<DSAPublicKeyField> dsaPublicKeyFields = new ArrayList<>();
        final ArrayList<TransitionalSignatureField> transitionalSignatureFields = new ArrayList<>();
        final OtrOutputStream out = new OtrOutputStream();
        for (final Field field : fields) {
            if (field instanceof InstanceTagField) {
                instanceTagFields.add((InstanceTagField) field);
            } else if (field instanceof ED448PublicKeyField) {
                publicKeyFields.add((ED448PublicKeyField) field);
            } else if (field instanceof ED448ForgingKeyField) {
                forgingKeyFields.add((ED448ForgingKeyField) field);
            } else if (field instanceof VersionsField) {
                versionsFields.add((VersionsField) field);
            } else if (field instanceof ExpirationDateField) {
                expirationDateFields.add((ExpirationDateField) field);
            } else if (field instanceof DSAPublicKeyField) {
                dsaPublicKeyFields.add((DSAPublicKeyField) field);
            } else if (field instanceof TransitionalSignatureField) {
                transitionalSignatureFields.add((TransitionalSignatureField) field);
                // Note: we need to skip the step of writing the transitional signature to the output stream, because
                // the transitional signature needs to be verified first, which means excluding the transitional
                // signature itself.
                continue;
            } else {
                throw new UnsupportedOperationException("BUG incomplete implementation: support for field type " + field.getClass() + " is not implemented yet.");
            }
            out.write(field);
        }
        if (instanceTagFields.size() != 1) {
            throw new ValidationException("Incorrect number of instance tag fields: " + instanceTagFields.size());
        }
        if (!isValidInstanceTag(instanceTagFields.get(0).instanceTag) || instanceTagFields.get(0).instanceTag == 0) {
            throw new ValidationException("Illegal instance tag.");
        }
        if (publicKeyFields.size() != 1) {
            throw new ValidationException("Incorrect number of public key fields: " + publicKeyFields.size());
        }
        final Point longTermPublicKey;
        try {
            verifyEdDSAPublicKey(publicKeyFields.get(0).publicKey);
            longTermPublicKey = publicKeyFields.get(0).publicKey;
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Illegal EdDSA long-term public key.", e);
        }
        if (forgingKeyFields.size() != 1) {
            throw new ValidationException("Incorrect number of forging key fields: " + forgingKeyFields.size());
        }
        try {
            // FIXME how should we exactly verify the forging key?
            verifyEdDSAPublicKey(forgingKeyFields.get(0).publicKey);
        } catch (OtrCryptoException e) {
            throw new ValidationException("Illegal Ed448 forging key.", e);
        }
        if (versionsFields.size() != 1) {
            throw new ValidationException("Incorrect number of versions fields: " + versionsFields.size());
        }
        if (!versionsFields.get(0).versions.contains(Session.OTRv.FOUR)) {
            throw new ValidationException("Expected at least OTR version 4 to be supported.");
        }
        if (expirationDateFields.size() != 1) {
            throw new ValidationException("Incorrect number of expiration date fields: " + expirationDateFields.size());
        }
        if (dsaPublicKeyFields.size() > 1) {
            throw new ValidationException("Expect either no or single DSA public key field. Found more than one.");
        }
        if (dsaPublicKeyFields.size() == 1 && transitionalSignatureFields.isEmpty()) {
            throw new ValidationException("DSA public key encountered without corresponding transitional signature.");
        }
        if (!now.before(new Date(expirationDateFields.get(0).timestamp * 1000))) {
            throw new ValidationException("Client Profile has expired.");
        }
        if (transitionalSignatureFields.size() > 1) {
            throw new ValidationException("Expected at most one transitional signature, got: " + transitionalSignatureFields.size());
        } else if (transitionalSignatureFields.size() == 1) {
            if (dsaPublicKeyFields.size() == 1) {
                // a DSA public key is available, hence we will validate the content with the transitional signature
                try {
                    final DSAPublicKey dsaPublicKey = dsaPublicKeyFields.get(0).publicKey;
                    final DSASignature transitionalSignature = transitionalSignatureFields.get(0).signature;
                    verifySignature(out.toByteArray(), dsaPublicKey, transitionalSignature.r, transitionalSignature.s);
                } catch (final OtrCryptoException e) {
                    throw new ValidationException("Failed transitional signature validation.", e);
                }
            }
            out.write(transitionalSignatureFields.get(0));
        }
        try {
            EdDSAKeyPair.verify(longTermPublicKey, out.toByteArray(), signature);
        } catch (final net.java.otr4j.crypto.ed448.ValidationException e) {
            throw new ValidationException("Verification of EdDSA signature failed.", e);
        }
    }

    /**
     * Type of fields.
     */
    private enum FieldType {
        /**
         * Client Profile owner instance tag (INT)
         */
        INSTANCE_TAG(0x0001),
        /**
         * Ed448 public key (ED448-PUBKEY)
         */
        LONG_TERM_EDDSA_PUBLIC_KEY(0x0002),
        /**
         * Ed448 forger public key (ED448-FORGER-PUBKEY)
         */
        ED448_FORGING_PUBLIC_KEY(0x0003),
        /**
         * Versions (DATA)
         *
         * A string corresponding to supported OTR protocol versions.
         */
        VERSIONS(0x0004),
        /**
         * Client Profile Expiration (CLIENT-PROF-EXP)
         * <p>
         * The expiration date represented in standard Unix 64-bit timestamp format. (Seconds as of midnight Jan 1, 1970
         * UTC, ignoring leap seconds.)
         */
        PROFILE_EXPIRATION(0x0005),
        /**
         * OTRv3 public authentication DSA key (PUBKEY)
         */
        TRANSITIONAL_DSA_PUBLIC_KEY(0x0006),
        /**
         * Transitional Signature (CLIENT-SIG)
         *
         * This signature is defined as a signature over fields 0x0001, 0x0002, 0x0003, 0x0004, 0x0005 and 0x006 only.
         */
        TRANSITIONAL_SIGNATURE(0x0007);

        private final int type;

        FieldType(final int type) {
            this.type = type;
        }

        /**
         * Find FieldType instance corresponding to the specified value.
         *
         * @param value The type value.
         * @return Returns the FieldType instance corresponding to the type value specified. Or null if type cannot be
         * found.
         */
        @Nullable
        private static FieldType findType(final int value) {
            for (final FieldType t : values()) {
                if (t.type == value) {
                    return t;
                }
            }
            return null;
        }
    }

    /**
     * Generic type for 'Field' type to express format in which various field types are implemented.
     */
    private interface Field extends OtrEncodable {
    }

    /**
     * Field for (owner) Instance Tag.
     */
    private static final class InstanceTagField implements Field {

        private static final FieldType TYPE = FieldType.INSTANCE_TAG;

        private final int instanceTag;

        private InstanceTagField(final int instanceTag) {
            this.instanceTag = instanceTag;
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeInt(this.instanceTag);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final InstanceTagField that = (InstanceTagField) o;
            return instanceTag == that.instanceTag;
        }

        @Override
        public int hashCode() {
            return Objects.hash(instanceTag);
        }
    }

    /**
     * Field for Ed448 public keys.
     */
    private static final class ED448PublicKeyField implements Field {

        private static final int ED448_PUBLIC_KEY_TYPE = 0x0010;
        private static final FieldType TYPE = FieldType.LONG_TERM_EDDSA_PUBLIC_KEY;

        private final Point publicKey;

        private ED448PublicKeyField(@Nonnull final Point publicKey) {
            this.publicKey = requireNonNull(publicKey);
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeShort(ED448_PUBLIC_KEY_TYPE);
            out.writePoint(this.publicKey);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final ED448PublicKeyField that = (ED448PublicKeyField) o;
            return Objects.equals(publicKey, that.publicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(publicKey);
        }
    }

    /**
     * Field for Ed448 forging keys.
     */
    private static final class ED448ForgingKeyField implements Field {

        private static final int ED448_FORGING_KEY_TYPE = 0x0012;
        private static final FieldType TYPE = FieldType.ED448_FORGING_PUBLIC_KEY;

        private final Point publicKey;

        private ED448ForgingKeyField(@Nonnull final Point publicKey) {
            this.publicKey = requireNonNull(publicKey);
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeShort(ED448_FORGING_KEY_TYPE);
            out.writePoint(this.publicKey);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final ED448ForgingKeyField that = (ED448ForgingKeyField) o;
            return Objects.equals(publicKey, that.publicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(publicKey);
        }
    }

    /**
     * Field for versions.
     */
    private static final class VersionsField implements Field {

        private static final FieldType TYPE = FieldType.VERSIONS;

        private final Set<Integer> versions;

        private VersionsField(@Nonnull final Set<Integer> versions) {
            this.versions = requireNonNull(versions);
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeData(encodeVersionString(versions).getBytes(US_ASCII));
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final VersionsField that = (VersionsField) o;
            return Objects.equals(versions, that.versions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(versions);
        }
    }

    /**
     * Field for expiration date.
     */
    private static final class ExpirationDateField implements Field {

        private static final FieldType TYPE = FieldType.PROFILE_EXPIRATION;

        private final long timestamp;

        private ExpirationDateField(final long timestamp) {
            this.timestamp = timestamp;
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeLong(this.timestamp);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final ExpirationDateField that = (ExpirationDateField) o;
            return timestamp == that.timestamp;
        }

        @Override
        public int hashCode() {
            return Objects.hash(timestamp);
        }
    }

    /**
     * Field for OTRv3 DSA public key.
     */
    private static final class DSAPublicKeyField implements Field {

        private static final FieldType TYPE = FieldType.TRANSITIONAL_DSA_PUBLIC_KEY;

        private final DSAPublicKey publicKey;

        private DSAPublicKeyField(@Nonnull final DSAPublicKey publicKey) {
            this.publicKey = requireNonNull(publicKey);
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writePublicKey(this.publicKey);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final DSAPublicKeyField that = (DSAPublicKeyField) o;
            return Objects.equals(publicKey, that.publicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(publicKey);
        }
    }

    /**
     * Field for transitional signature.
     */
    private static final class TransitionalSignatureField implements Field {

        private static final FieldType TYPE = FieldType.TRANSITIONAL_SIGNATURE;

        private final DSASignature signature;

        private TransitionalSignatureField(@Nonnull final DSASignature signature) {
            this.signature = requireNonNull(signature);
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeBigInt(this.signature.r);
            out.writeBigInt(this.signature.s);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final TransitionalSignatureField that = (TransitionalSignatureField) o;
            return Objects.equals(signature, that.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(signature);
        }
    }
}
