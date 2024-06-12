package exception;

public class DecryptException extends DigitalEnvelopeException {
    public DecryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
