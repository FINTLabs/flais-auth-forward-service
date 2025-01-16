package no.fintlabs.oidc;

public class InvalidState extends SecurityException {
    public InvalidState() {
        super("Invalid state");
    }
}