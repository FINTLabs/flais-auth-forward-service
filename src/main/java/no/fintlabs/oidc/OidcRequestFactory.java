package no.fintlabs.oidc;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.session.Session;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

import static no.fintlabs.Headers.*;

@Slf4j
@Component
public class OidcRequestFactory {

    @Value("${spring.webflux.base-path:/}")
    private String basePath;

    private final OidcConfiguration oidcConfiguration;

    public OidcRequestFactory(OidcConfiguration oidcConfiguration) {
        this.oidcConfiguration = oidcConfiguration;
    }

    public static MultiValueMap<String, String> createTokenRequestBody(String clientId, String clientSecret, String code, String callbackUri) {

        final MultiValueMap<String, String> bodyMap = new LinkedMultiValueMap<>();

        bodyMap.add("grant_type", "authorization_code");
        bodyMap.add("client_id", clientId);
        bodyMap.add("client_secret", clientSecret);
        bodyMap.add("code", code);
        bodyMap.add("redirect_uri", callbackUri);

        return bodyMap;
    }

    public URI createAuthorizationUri(String authorizationEndpoint, HttpHeaders headers, Session session) {
        return UriComponentsBuilder.fromUriString(authorizationEndpoint)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", createCallbackUri(headers))
                .queryParam("state", session.getState())
                .queryParam("nonce", RandomStringUtils.randomAlphanumeric(32))
                //.queryParam("code_challenge", PkceUtil.generateCodeChallange(PkceUtil.generateCodeVerifier()))
                //        .queryParam("code_challenge_method", "S256")
                .queryParam("client_id", oidcConfiguration.getClientId())
                .queryParam("scope", String.join("+", oidcConfiguration.getScopes()))
                .build()
                .toUri();
    }

    public String createCallbackUri(HttpHeaders headers) {
        return UriComponentsBuilder.newInstance()
                .scheme(getProtocol(headers))
                .port(getPort(headers))
                .host(headers.getFirst(X_FORWARDED_HOST))
                .path(basePath)
                .path("/_oauth/callback")
                .build()
                .toUriString();
    }

    public URI createRedirectAfterLoginUri(HttpHeaders headers) {
        URI redirectUri = UriComponentsBuilder.newInstance()
                .scheme(getProtocol(headers))
                .port(getPort(headers))
                .host(headers.getFirst(X_FORWARDED_HOST))
                .path(basePath)
                .path(oidcConfiguration.getRedirectAfterLoginUri().toString())
                .build()
                .toUri();

        log.debug("Redirecting to {}", redirectUri);

        return redirectUri;
    }

    public URI createRedirectAfterLogoutUri() {


        if (oidcConfiguration.getRedirectAfterLogoutUri().isAbsolute()) {
            return oidcConfiguration.getRedirectAfterLogoutUri();
        }
        return UriComponentsBuilder.newInstance()
                .path(basePath)
                .path(oidcConfiguration.getRedirectAfterLogoutUri().toString())
                .build()
                .toUri();
    }

    public String getPort(HttpHeaders headers) {
        if (oidcConfiguration.isEnforceHttps()) {
            return null;
        }

        if (headers.containsKey(X_FORWARDED_PORT)) {
            return headers.getFirst(X_FORWARDED_PORT).equals("80") ? null : headers.getFirst(X_FORWARDED_PORT);
        }

        return null;
    }

    public String getProtocol(HttpHeaders headers) {
        return oidcConfiguration.isEnforceHttps() ? "https" : headers.getFirst(X_FORWARDED_PROTO);
    }
}
