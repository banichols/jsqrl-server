package org.jsqrl.error;

/**
 * The base SQRL Exception class.
 * Declared as a RuntimeException so that the framework
 * can handle the exception if need be.
 * <p>
 * Created by Brent Nichols
 */
public class SqrlException extends RuntimeException {

    public SqrlException(String message) {
        super(message);
    }

    public SqrlException(String message, Throwable cause) {
        super(message, cause);
    }
}
