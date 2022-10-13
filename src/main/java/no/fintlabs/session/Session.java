package no.fintlabs.session;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Data;
import no.fintlabs.oidc.Token;

import java.time.LocalDateTime;
import java.util.Date;

@Data
@Builder
public class Session {
    @JsonIgnore
    private Token token;
    @JsonIgnore
    private String codeVerifier;
    private LocalDateTime expires;
    private String upn;
}
