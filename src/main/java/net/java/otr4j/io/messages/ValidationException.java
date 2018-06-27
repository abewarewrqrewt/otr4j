package net.java.otr4j.io.messages;

import net.java.otr4j.api.OtrException;

import javax.annotation.Nonnull;

/**
 * Validation Exception, indicating that some part of the message failed validation.
 */
public final class ValidationException extends OtrException {

    ValidationException(@Nonnull final String message) {
        super(message);
    }

    ValidationException(@Nonnull final String message, @Nonnull final Throwable cause) {
        super(message, cause);
    }
}
