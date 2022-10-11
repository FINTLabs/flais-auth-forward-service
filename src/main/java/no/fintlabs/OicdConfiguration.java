package no.fintlabs;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "fint.sso")
public class OicdConfiguration {
    private String clientId;
    private String clientSecret;
    private String issuerUri = "https://idp.felleskomponent.no/nidp/oauth/nam";
    private List<String> scopes = Arrays.asList("end-user-profile", "openid");
    private long sessionMaxAgeInMinutes = 5;
}
