package exception;

public class DigitalEnvelopeException extends Exception {
    public DigitalEnvelopeException(String message) {
        super(message);
    }

    public DigitalEnvelopeException(String message, Throwable cause) {
        super(message, cause);
    }
}
