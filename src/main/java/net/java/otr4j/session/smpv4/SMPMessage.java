/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.io.OtrEncodable;

@SuppressWarnings("PMD.ConstantsInInterface")
interface SMPMessage extends OtrEncodable {
    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    int SMP1 = 0x0002;
    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    int SMP2 = 0x0003;
    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    int SMP3 = 0x0004;
    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    int SMP4 = 0x0005;
    /**
     * The message indicates any in-progress SMP session must be aborted.
     */
    int SMP_ABORT = 0x0006;
}
