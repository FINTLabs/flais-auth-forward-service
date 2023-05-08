package no.fintlabs;

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
public class ApplicationConfiguration {
    private String clientId;
    private String clientSecret;
    private String idpHostname;
    private List<String> scopes = Arrays.asList("end-user-profile", "openid");
    private long sessionMaxAgeInMinutes = 1440;
    private boolean enforceHttps = true;
    private URI redirectAfterLogoutUri = URI.create("/_oauth/logged-out");
    private URI redirectAfterLoginUri = URI.create("/");
    private String logoutMessage;
    private boolean verifyTokenSignature = true;
    private long secondsBeforeTokenRefresh = 60;

    public UriComponentsBuilder getIssuerUri() {
        return UriComponentsBuilder.fromUri(URI.create(String.format("https://%s/nidp/oauth/nam", idpHostname)));
    }
}
