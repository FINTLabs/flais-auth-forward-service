package no.fintlabs.oidc;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import no.fintlabs.session.Session;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Optional;

import static no.fintlabs.controller.Headers.*;

@Slf4j
@Component
public class OidcRequestFactory {

    @Value("${spring.webflux.base-path:/}")
    private String basePath;

    private final ApplicationConfiguration applicationConfiguration;

    public OidcRequestFactory(ApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    public static MultiValueMap<String, String> createTokenRequestBody(String clientId, String clientSecret, String code, String callbackUri, String codeVerifier) {

        final MultiValueMap<String, String> bodyMap = new LinkedMultiValueMap<>();

        bodyMap.add("grant_type", "authorization_code");
        bodyMap.add("client_id", clientId);
        bodyMap.add("client_secret", clientSecret);
        bodyMap.add("code", code);
        bodyMap.add("redirect_uri", callbackUri);
        bodyMap.add("code_verifier", codeVerifier);

        return bodyMap;
    }

    public static MultiValueMap<String, String> createRefreshTokenRequestBody(String clientId, String clientSecret, String refreshToken) {

        final MultiValueMap<String, String> bodyMap = new LinkedMultiValueMap<>();

        bodyMap.add("grant_type", "refresh_token");
        bodyMap.add("client_id", clientId);
        bodyMap.add("client_secret", clientSecret);
        bodyMap.add("refresh_token", refreshToken);

        return bodyMap;
    }

    public static MultiValueMap<String, String> createRevokeTokenRequestBody(String clientId, String clientSecret, String refreshToken) {
        final MultiValueMap<String, String> bodyMap = new LinkedMultiValueMap<>();

        bodyMap.add("client_id", clientId);
        bodyMap.add("client_secret", clientSecret);
        bodyMap.add("token", refreshToken);

        return bodyMap;
    }

    public URI createAuthorizationUri(String authorizationEndpoint, HttpHeaders headers, String state, String codeVerifier) {
        return UriComponentsBuilder.fromUriString(authorizationEndpoint)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", createCallbackUri(headers))
                .queryParam("state", state)
                .queryParam("nonce", RandomStringUtils.randomAlphanumeric(32))
                .queryParam("prompt", "login")
                .queryParam("code_challenge", PkceUtil.generateCodeChallenge(codeVerifier))
                .queryParam("code_challenge_method", PkceUtil.codeChallengeMethod)
                .queryParam("client_id", applicationConfiguration.getClientId())
                .queryParam("scope", String.join("+", applicationConfiguration.getScopes()))
                .build()
                .toUri();
    }

    public String createCallbackUri(HttpHeaders headers) {
        return UriComponentsBuilder.newInstance()
                .scheme(getProtocol(headers))
                .port(getPort(headers))
                .host(getHost(headers))
                .path(basePath)
                .path("/_oauth/callback")
                .build()
                .toUriString();
    }

    public URI createRedirectAfterLoginUri(HttpHeaders headers) {
        URI redirectUri = UriComponentsBuilder.newInstance()
                .scheme(getProtocol(headers))
                .port(getPort(headers))
                .host(getHost(headers))
                .path(basePath)
                .path(applicationConfiguration.getRedirectAfterLoginUri().toString())
                .build()
                .toUri();

        log.debug("Redirecting to {}", redirectUri);

        return redirectUri;
    }

    public URI createRedirectAfterLogoutUri() {


        if (applicationConfiguration.getRedirectAfterLogoutUri().isAbsolute()) {
            return applicationConfiguration.getRedirectAfterLogoutUri();
        }
        return UriComponentsBuilder.newInstance()
                .path(basePath)
                .path(applicationConfiguration.getRedirectAfterLogoutUri().toString())
                .build()
                .toUri();
    }

    public String getPort(HttpHeaders headers) {
        if (applicationConfiguration.isEnforceHttps()) {
            return null;
        }

        if (headers.containsKey(X_FORWARDED_PORT)) {
            return headers.getFirst(X_FORWARDED_PORT).equals("80") ? null : headers.getFirst(X_FORWARDED_PORT);
        }

        return Optional.ofNullable(headers.getFirst(HttpHeaders.HOST))
                .map(host -> host.contains(":") ? host.split(":")[1] : null)
                .orElse(null);
    }

    public String getProtocol(HttpHeaders headers) {
        if (applicationConfiguration.isEnforceHttps()) {
            return "https";
        }
        return Optional.ofNullable(headers.getFirst(X_FORWARDED_PROTO)).orElse("http");
    }

    public String getHost(HttpHeaders headers) {
        return Optional.ofNullable(headers.getFirst(X_FORWARDED_HOST))
                .orElse(Optional.ofNullable(headers.getFirst(HttpHeaders.HOST))
                        .map(host -> host.contains(":") ? host.split(":")[0] : host)
                        .orElse(null));
    }
}
