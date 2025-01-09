package no.fintlabs.session;

import lombok.Builder;
import lombok.Data;
import no.fintlabs.oidc.Token;

import java.time.LocalDateTime;

@Data
@Builder
public class Session {
    private Token token;

    private String sessionId;

    private LocalDateTime sessionStartAt;
    private LocalDateTime tokenExpiresAt;
    private String upn;
}
