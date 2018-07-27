/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io;

/**
 * Serialization constants.
 *
 * @author George Politis
 */
final class EncodingConstants {

    static final String HEAD = "?OTR";
    static final char HEAD_ENCODED = ':';
    static final char HEAD_FRAGMENTED_V2 = ',';
    static final char HEAD_FRAGMENTED_V3 = '|';
    static final char HEAD_ERROR = ' ';
    static final char HEAD_QUERY_Q = '?';
    static final char HEAD_QUERY_V = 'v';
    static final char TAIL_FRAGMENTED = ',';
    static final String ERROR_PREFIX = "Error:";

    static final int TYPE_LEN_BYTE = 1;
    static final int TYPE_LEN_SHORT = 2;
    static final int TYPE_LEN_INT = 4;
    static final int TYPE_LEN_LONG = 8;
    static final int TYPE_LEN_MAC = 20;
    static final int TYPE_LEN_MAC_OTR4 = 64;
    static final int TYPE_LEN_CTR = 8;

    // XSalsa20 IV (nonce)
    static final int TYPE_LEN_NONCE = 24;

    static final int DATA_LEN = TYPE_LEN_INT;
    static final int TLV_LEN = TYPE_LEN_SHORT;

    /**
     * Public Key type DSA type value for serialization.
     */
    static final int PUBLIC_KEY_TYPE_DSA = 0;

    static final int EDDSA_SIGNATURE_LENGTH_BYTES = 114;

    private EncodingConstants() {
        // No need to instantiate class.
    }
}
