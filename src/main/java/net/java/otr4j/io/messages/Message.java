/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io.messages;

// TODO In future we should move the message type integers outside the message type class hierarchy. These are only really necessary for (de)serialization.
public interface Message {

    // Encoded message types
    int MESSAGE_DH_COMMIT = 0x02;
    int MESSAGE_DATA = 0x03;
    int MESSAGE_DHKEY = 0x0a;
    int MESSAGE_REVEALSIG = 0x11;
    int MESSAGE_SIGNATURE = 0x12;

    /**
     * Get byte code for message type.
     *
     * This method is intended solely for use to serialize an OTR message with
     * an appropriate message type. This value should not be used to determine
     * its Java class type.
     *
     * @return Returns byte value for message type.
     */
    int getType();
}
