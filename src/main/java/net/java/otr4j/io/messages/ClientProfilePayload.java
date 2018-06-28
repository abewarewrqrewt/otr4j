package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.EdDSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine.DSASignature;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.profile.ClientProfile;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.InstanceTag.isValidInstanceTag;
import static net.java.otr4j.crypto.OtrCryptoEngine.signRS;
import static net.java.otr4j.crypto.OtrCryptoEngine.verify;
import static net.java.otr4j.crypto.OtrCryptoEngine4.verifyEdDSAPublicKey;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.io.SerializationUtils.ASCII;
import static net.java.otr4j.io.SerializationUtils.encodeVersionString;
import static net.java.otr4j.io.SerializationUtils.parseVersionString;
import static net.java.otr4j.util.Iterables.findByType;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * The client profile payload.
 * <p>
 * This is the client profile in a representation that is easily serializable and that is able to carry the signatures
 * corresponding to the client profile.
 */
// FIXME write unit tests
// FIXME everywhere where ClientProfilePayload is validated, ensure that owner instance tag matches with sender instance tag of message.
public final class ClientProfilePayload implements OtrEncodable {

    // FIXME constant public key ID can probably be cleared once OTRv4 spec settles down on protocol design
    private static final int SINGLE_LONG_TERM_PUBLIC_KEY_ID = 1;

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
    private ClientProfilePayload(@Nonnull final List<Field> fields, @Nonnull final byte[] signature) {
        try {
            validate(fields, signature, new Date());
        } catch (final ValidationException e) {
            throw new IllegalArgumentException("Invalid client profile fields.", e);
        }
        this.fields = fields;
        this.signature = signature;
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
                                            @Nullable final DSAPrivateKey dsaPrivateKey,
                                            @Nonnull final EdDSAKeyPair eddsaKeyPair) {
        final ArrayList<Field> fields = new ArrayList<>();
        fields.add(new InstanceTagField(profile.getInstanceTag()));
        fields.add(new ED448PublicKeyField(SINGLE_LONG_TERM_PUBLIC_KEY_ID, profile.getLongTermPublicKey()));
        fields.add(new VersionsField(profile.getVersions()));
        fields.add(new ExpirationDateField(profile.getExpirationUnixTime()));
        final DSAPublicKey dsaPublicKey = profile.getDsaPublicKey();
        if (dsaPublicKey != null) {
            fields.add(new DSAPublicKeyField(dsaPublicKey));
        }
        final byte[] partialM;
        try (final OtrOutputStream out = new OtrOutputStream()) {
            for (final Field field : fields) {
                out.write(field);
            }
            partialM = out.toByteArray();
        }
        final byte[] m;
        if (dsaPrivateKey != null) {
            if (dsaPublicKey == null) {
                throw new IllegalArgumentException("DSA private key provided for transitional signature, but DSA public key is not present in the client profile.");
            }
            final DSASignature transitionalSignature = signRS(partialM, dsaPrivateKey);
            final TransitionalSignatureField sigField = new TransitionalSignatureField(transitionalSignature);
            fields.add(sigField);
            m = concatenate(partialM, encode(sigField));
        } else {
            m = partialM;
        }
        final byte[] signature = eddsaKeyPair.sign(m);
        return new ClientProfilePayload(fields, signature);
    }

    /**
     * Read Client Profile payload from OTR-encoded input stream.
     *
     * @param in The OTR-encoded input stream.
     * @return Returns ClientProfilePayload as read from input stream.
     * @throws IOException        Throws IOException in case of reading failure.
     * @throws OtrCryptoException In case of failure to restore cryptographic components in the payload.
     */
    @Nonnull
    static ClientProfilePayload readFrom(@Nonnull final OtrInputStream in) throws IOException, OtrCryptoException {
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
                case LONG_TERM_EdDSA_PUBLIC_KEY:
                    final int identifier = in.readInt();
                    final int publicKeyType = in.readShort();
                    switch (publicKeyType) {
                        case ED448PublicKeyField.ED448_PUBLIC_KEY_TYPE:
                            final Point publicKey = in.readPoint();
                            fields.add(new ED448PublicKeyField(identifier, publicKey));
                            break;
                        default:
                            throw new ProtocolException("Unsupported Ed448 public key type: " + publicKeyType);
                    }
                    break;
                case VERSIONS:
                    final Set<Integer> versions = parseVersionString(new String(in.readData(), ASCII));
                    fields.add(new VersionsField(versions));
                    break;
                case PROFILE_EXPIRATION:
                    fields.add(new ExpirationDateField(in.readLong()));
                    break;
                case TRANSITIONAL_SIGNATURE:
                    final BigInteger r = in.readBigInt();
                    final BigInteger s = in.readBigInt();
                    fields.add(new TransitionalSignatureField(new DSASignature(r, s)));
                    break;
                default:
                    throw new ProtocolException("Unknown field type encountered: " + type);
            }
        }
        final byte[] signature = in.readEdDSASignature();
        return new ClientProfilePayload(fields, signature);
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
     * This method is expected to succeed always. Validation should be performed prior to calling this method to ensure
     * that a valid composition of fields is available.
     *
     * @return Returns reconstructed client profile from fields and signatures stored inside the payload.
     */
    @Nonnull
    private ClientProfile reconstructClientProfile() {
        final int instanceTag = findByType(this.fields, InstanceTagField.class).instanceTag;
        final Point longTermPublicKey = findByType(this.fields, ED448PublicKeyField.class).publicKey;
        final Set<Integer> versions = findByType(this.fields, VersionsField.class).versions;
        final long expirationUnixTime = findByType(this.fields, ExpirationDateField.class).timestamp;
        final DSAPublicKeyField dsaPublicKeyField = findByType(this.fields, DSAPublicKeyField.class, null);
        return new ClientProfile(instanceTag, longTermPublicKey, versions, expirationUnixTime,
            dsaPublicKeyField == null ? null : dsaPublicKeyField.publicKey);
    }

    /**
     * Verify consistency of fields list.
     *
     * @param fields    List of fields.
     * @param signature The OTRv4 signature for the fields contained in the client profile.
     * @throws ValidationException In case ClientProfilePayload contents are not inconsistent or signature is invalid.
     */
    private static void validate(@Nonnull final List<Field> fields, @Nonnull final byte[] signature, @Nonnull final Date now) throws ValidationException {
        // TODO not very elegant way of implementing. This can probably be done much nicer.
        final ArrayList<InstanceTagField> instanceTagFields = new ArrayList<>();
        final ArrayList<ED448PublicKeyField> publicKeyFields = new ArrayList<>();
        final ArrayList<VersionsField> versionsFields = new ArrayList<>();
        final ArrayList<ExpirationDateField> expirationDateFields = new ArrayList<>();
        final ArrayList<DSAPublicKeyField> dsaPublicKeyFields = new ArrayList<>();
        final ArrayList<TransitionalSignatureField> transitionalSignatureFields = new ArrayList<>();
        // FIXME should we enforce strict order? Not in currently.
        for (final Field field : fields) {
            if (field instanceof InstanceTagField) {
                instanceTagFields.add((InstanceTagField) field);
            } else if (field instanceof ED448PublicKeyField) {
                publicKeyFields.add((ED448PublicKeyField) field);
            } else if (field instanceof VersionsField) {
                versionsFields.add((VersionsField) field);
            } else if (field instanceof ExpirationDateField) {
                expirationDateFields.add((ExpirationDateField) field);
            } else if (field instanceof DSAPublicKeyField) {
                dsaPublicKeyFields.add((DSAPublicKeyField) field);
            } else if (field instanceof TransitionalSignatureField) {
                transitionalSignatureFields.add((TransitionalSignatureField) field);
            } else {
                throw new UnsupportedOperationException("Incomplete implementation: support for field type " + field.getClass() + " is not implemented yet.");
            }
        }
        if (instanceTagFields.size() != 1) {
            throw new ValidationException("Incorrect number of instance tag fields: " + instanceTagFields.size());
        }
        if (!isValidInstanceTag(instanceTagFields.get(0).instanceTag)) {
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
        if (!now.before(new Date(expirationDateFields.get(0).timestamp * 1000))) {
            throw new ValidationException("Client Profile has expired.");
        }
        final byte[] partialM;
        try (final OtrOutputStream out = new OtrOutputStream()) {
            out.write(instanceTagFields.get(0));
            out.write(publicKeyFields.get(0));
            out.write(versionsFields.get(0));
            out.write(expirationDateFields.get(0));
            if (dsaPublicKeyFields.size() == 1) {
                out.write(dsaPublicKeyFields.get(0));
            }
            partialM = out.toByteArray();
        }
        final byte[] m;
        if (transitionalSignatureFields.size() > 1) {
            throw new ValidationException("Expected at most one transitional signature, got: " + transitionalSignatureFields.size());
        } else if (transitionalSignatureFields.size() == 1) {
            try {
                if (dsaPublicKeyFields.size() != 1) {
                    throw new ValidationException("DSA public key is missing. It is impossible to verify the transitional signature.");
                }
                final DSAPublicKey dsaPublicKey = dsaPublicKeyFields.get(0).publicKey;
                final DSASignature transitionalSignature = transitionalSignatureFields.get(0).signature;
                verify(partialM, dsaPublicKey, transitionalSignature.r, transitionalSignature.s);
            } catch (final OtrCryptoException e) {
                throw new ValidationException("Failed transitional signature validation.", e);
            }
            m = concatenate(partialM, encode(transitionalSignatureFields.get(0)));
        } else {
            m = partialM;
        }
        try {
            EdDSAKeyPair.verify(longTermPublicKey, m, signature);
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Verification of EdDSA signature failed.", e);
        }
    }

    /**
     * Type of fields.
     */
    private enum FieldType {
        /**
         * The instance tag of the client/device that created the Client Profile.
         */
        INSTANCE_TAG(0x0001),
        /**
         * The Client's Ed448 long-term public key.
         */
        LONG_TERM_EdDSA_PUBLIC_KEY(0x0002),
        /**
         * A string corresponding to supported OTR protocol versions.
         */
        VERSIONS(0x0003),
        /**
         * The expiration date.
         * <p>
         * The expiration date represented in standard Unix 64-bit timestamp format. (Seconds as of midnight Jan 1, 1970
         * UTC, ignoring leap seconds.)
         */
        PROFILE_EXPIRATION(0x0004),
        /**
         * This signature is a signature over fields of type: {@link #INSTANCE_TAG}, {@link #LONG_TERM_EdDSA_PUBLIC_KEY},
         * {@link #VERSIONS} and {@link #PROFILE_EXPIRATION}.
         */
        TRANSITIONAL_SIGNATURE(0x0005);

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
    }

    /**
     * Field for Ed448 public keys.
     */
    private static final class ED448PublicKeyField implements Field {

        private static final int ED448_PUBLIC_KEY_TYPE = 0x0010;
        private static final FieldType TYPE = FieldType.LONG_TERM_EdDSA_PUBLIC_KEY;

        private final int identifier;
        private final Point publicKey;

        private ED448PublicKeyField(final int identifier, @Nonnull final Point publicKey) {
            this.identifier = identifier;
            this.publicKey = requireNonNull(publicKey);
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeInt(this.identifier);
            out.writeShort(ED448_PUBLIC_KEY_TYPE);
            out.writePoint(this.publicKey);
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
            out.writeData(encodeVersionString(versions).getBytes(ASCII));
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
    }

    /**
     * Field for OTRv3 DSA public key.
     */
    private static final class DSAPublicKeyField implements Field {

        private final DSAPublicKey publicKey;

        private DSAPublicKeyField(@Nonnull final DSAPublicKey publicKey) {
            this.publicKey = requireNonNull(publicKey);
        }

        @Override
        public void writeTo(@Nonnull final OtrOutputStream out) {
            out.writePublicKey(this.publicKey);
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
    }
}
