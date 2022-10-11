package no.fintlabs.session;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Builder;
import lombok.Data;
import no.fintlabs.oidc.Token;

import java.util.Date;

@Data
@Builder
public class Session {
    @JsonIgnore
    private Token token;
    @JsonIgnore
    private String codeVerifier;
    private Date expires;
    private String upn;
}
