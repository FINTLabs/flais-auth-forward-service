package no.fintlabs.session;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Data;
import no.fintlabs.oidc.Token;

import java.time.LocalDateTime;

@Data
@Builder
public class Session {
    @JsonIgnore
    private Token token;

    @JsonIgnore
    private String codeVerifier;

    private String sessionId;

    private LocalDateTime sessionStartAt;
    private LocalDateTime tokenExpiresAt;
    private String upn;
}
