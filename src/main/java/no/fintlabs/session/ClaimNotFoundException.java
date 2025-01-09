package no.fintlabs.session;

public class ClaimNotFoundException extends SecurityException {
    public ClaimNotFoundException() {}

    public ClaimNotFoundException(String message) {
        super(message);
    }
}
