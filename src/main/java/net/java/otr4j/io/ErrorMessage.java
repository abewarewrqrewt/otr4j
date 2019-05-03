/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.io;

import java.util.Objects;
import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

/**
 * OTRv2/3/4 OTR error message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class ErrorMessage implements Message {

    /**
     * Identifier for error case "Unreadable message."
     */
    public static final String ERROR_ID_UNREADABLE_MESSAGE = "ERROR_1";

    /**
     * Identifier for error case "Not in private state."
     */
    public static final String ERROR_ID_NOT_IN_PRIVATE_STATE = "ERROR_2";

    /**
     * Message for error case "Unreadable message."
     */
    public static final String ERROR_1_MESSAGE_UNREADABLE_MESSAGE = "The message is undecryptable.";

    /**
     * Message for error case "Not in private state."
     */
    public static final String ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE = "The message arrived in a state that is not encrypted messages.";

    /**
     * Identifier in case of predefined OTRv4 error message.
     */
    public final String identifier;

    /**
     * The error message.
     */
    public final String error;

    /**
     * Constructor for Error Message type.
     *
     * @param identifier The OTRv4 identifier for predefined error messages. Use empty-string if custom error message.
     * @param error      The error message.
     */
    public ErrorMessage(@Nonnull final String identifier, @Nonnull final String error) {
        this.identifier = requireNonNull(identifier);
        this.error = requireNonNull(error);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + Objects.hashCode(this.error);
        return hash;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ErrorMessage other = (ErrorMessage) obj;
        return Objects.equals(this.error, other.error);
    }
}
