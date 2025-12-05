package no.fintlabs.controller;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.oidc.InvalidState;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public String handleSecurityException(Exception e) throws ResponseStatusException {
        if (e instanceof ResponseStatusException rse) { throw rse; }

        log.debug(e.toString());
        String reason = "";

        if (e instanceof InvalidState) {
            reason = "Innloggingsøkten har utløpt";
        }

        return "redirect:/_oauth/error?reason=" +
                URLEncoder.encode(reason, StandardCharsets.UTF_8);
    }
}