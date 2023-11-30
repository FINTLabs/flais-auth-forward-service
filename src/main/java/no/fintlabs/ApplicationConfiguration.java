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
    private UriComponentsBuilder issuerUri = UriComponentsBuilder.fromUri(URI.create("https://idp.felleskomponent.no/nidp/oauth/nam"));
    private List<String> scopes = Arrays.asList("end-user-profile", "openid");
    private long sessionMaxAgeInMinutes = 1440;
    private boolean enforceHttps = true;
    private URI redirectAfterLogoutUri = URI.create("/_oauth/logged-out");
    private URI redirectAfterLoginUri = URI.create("/");
    private String logoutMessage;
    private boolean verifyTokenSignature = true;
    private long secondsBeforeTokenRefresh = 60;
    private String claimForUpn = "email";

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = UriComponentsBuilder.fromUri(URI.create(issuerUri));
    }

}
