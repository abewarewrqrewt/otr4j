package net.java.otr4j.session.smpv4;

import javax.annotation.Nonnull;

final class SMPAbortException extends Exception {

    private static final long serialVersionUID = 3561843234075404537L;

    SMPAbortException(@Nonnull final String message) {
        super(message);
    }
}
