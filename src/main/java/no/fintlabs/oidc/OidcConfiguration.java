package no.fintlabs.oidc;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "fint.sso")
public class OidcConfiguration {
    private String clientId;
    private String clientSecret;
    private UriComponentsBuilder issuerUri = UriComponentsBuilder.fromUri(URI.create("https://idp.felleskomponent.no/nidp/oauth/nam"));
    private List<String> scopes = Arrays.asList("end-user-profile", "openid");
    private long sessionMaxAgeInMinutes = 5;
    private boolean enforceHttps = true;
    private URI redirectAfterLogoutUri = URI.create("/logged-out");
    private URI redirectAfterLoginUri = URI.create("/");
    private String logoutMessage;
}
