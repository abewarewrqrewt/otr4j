/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.TLV;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import java.util.List;

/**
 * StateEncrypted represents the <i>Encrypted</i> messaging states.
 * <p>
 * The StateEncrypted interface reduces the freedom allowed by messaging states such that there are more guarantees when
 * working with any kind of encrypted messaging state.
 */
public interface StateEncrypted extends State {

    @Nonnull
    @Override
    SMPHandler getSmpHandler();

    @Nonnull
    @Override
    AbstractEncodedMessage transformSending(@Nonnull Context context, @Nonnull String msgText, @Nonnull List<TLV> tlvs,
            byte flags) throws OtrException;
}
