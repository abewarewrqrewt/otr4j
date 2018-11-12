/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;

/**
 * Utility class for DataMessage4.
 */
public final class DataMessage4s {

    private DataMessage4s() {
        // No need to instantiate.
    }

    /**
     * Encode data message sections from provided DataMessage4 instance and return the byte-encoded representation.
     *
     * @param message the message instance
     * @return Returns the byte-encoded representation of the data message sections of the message.
     */
    @Nonnull
    public static byte[] encodeDataMessageSections(@Nonnull final DataMessage4 message) {
        final OtrOutputStream out = new OtrOutputStream();
        message.writeDataMessageSections(out);
        return out.toByteArray();
    }
}
