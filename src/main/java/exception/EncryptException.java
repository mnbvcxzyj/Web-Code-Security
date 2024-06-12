package exception;

public class EncryptException extends DigitalEnvelopeException {
    public EncryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
