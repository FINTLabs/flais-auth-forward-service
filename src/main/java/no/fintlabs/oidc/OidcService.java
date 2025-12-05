package no.fintlabs.oidc;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import no.fintlabs.controller.FetchTokenError;
import no.fintlabs.controller.TokenRefreshError;
import no.fintlabs.session.Session;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;
import static com.auth0.jwt.algorithms.Algorithm.none;

@Slf4j
@Service
public class OidcService {

    public static final String WELL_KNOWN_OPENID_CONFIGURATION_PATH = ".well-known/openid-configuration";

    private final ApplicationConfiguration applicationConfiguration;
    private final WebClient webClient;

    @Getter
    @Setter
    private WellKnownConfiguration wellKnownConfiguration;

    private final OidcRequestFactory oidcRequestFactory;

    private final CodeVerifierCache codeVerifierCache;

    @Getter
    @Setter
    private Jwk jwk;

    public static final Integer RETRY_ATTEMPTS = 3;
    public static final Duration DELAY = Duration.ofSeconds((long) Math.pow(1L, 5L));

    public OidcService(ApplicationConfiguration applicationConfiguration, WebClient webClient, OidcRequestFactory oidcRequestFactory, CodeVerifierCache codeVerifierCache) {
        this.applicationConfiguration = applicationConfiguration;
        this.webClient = webClient;
        this.oidcRequestFactory = oidcRequestFactory;
        this.codeVerifierCache = codeVerifierCache;
    }

    @PostConstruct
    public void init() {
        fetchWellKnowConfiguration();
        fetchJwks();
    }

    public Mono<Token> fetchToken(Map<String, String> params, HttpHeaders headers) {
        log.debug("Fetching token from {}", getWellKnownConfiguration().getTokenEndpoint() + "?resourceServer=fint-api");

        var codeVerifier = codeVerifierCache.getCodeVerifier(params.get("state"));
        if (codeVerifier == null) {
            log.debug("No code verifier found for {}", params.get("state"));
            return Mono.error(new InvalidState());
        }

        return webClient.post()
                .uri(getWellKnownConfiguration().getTokenEndpoint() + "?resourceServer=fint-api")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(
                        BodyInserters
                                .fromFormData(
                                        OidcRequestFactory.createTokenRequestBody(
                                                applicationConfiguration.getClientId(),
                                                applicationConfiguration.getClientSecret(),
                                                params.get("code"),
                                                oidcRequestFactory.createCallbackUri(headers),
                                                codeVerifier
                                        ))
                )
                .retrieve()
                .bodyToMono(Token.class)
                .retryWhen(Retry.fixedDelay(RETRY_ATTEMPTS, DELAY)
                        .doAfterRetry(retrySignal -> log.debug("Fetch token retried {} times.", retrySignal.totalRetries()))
                        .onRetryExhaustedThrow(((retryBackoffSpec, retrySignal) -> retrySignal.failure()))
                )
                .doOnSuccess(token -> {
                    codeVerifierCache.removeCodeVerifier(params.get("state"));
                    log.debug("Successfully got token for: {}", token.getAccessToken());
                })
                .onErrorMap(ex -> {
                    log.debug("Error fetching token", ex);
                    return new FetchTokenError();
                });
    }

    private void logToken(Token token) {
        log.debug("Got token: ...{}", token.getAccessToken()
                .substring(token.getAccessToken().length() - 15));
    }

    public Mono<Token> refreshToken(String sessionId, Token token) {
        log.debug("Refreshing token from {}", getWellKnownConfiguration().getTokenEndpoint() + "?resourceServer=fint-api");

        return webClient.post()
                .uri(getWellKnownConfiguration().getTokenEndpoint() + "?resourceServer=fint-api")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(
                        BodyInserters
                                .fromFormData(
                                        OidcRequestFactory.createRefreshTokenRequestBody(
                                                applicationConfiguration.getClientId(),
                                                applicationConfiguration.getClientSecret(),
                                                token.getRefreshToken()
                                        ))
                )
                .retrieve()
                .bodyToMono(Token.class)
                .retryWhen(Retry.fixedDelay(RETRY_ATTEMPTS, DELAY)
                        .doAfterRetry(retrySignal -> log.debug("Refresh token retried {} times.", retrySignal.totalRetries()))
                        .onRetryExhaustedThrow(((retryBackoffSpec, retrySignal) -> retrySignal.failure()))
                )
                .doOnSuccess(tokenResponse -> log.debug("Successfully refreshed token for: {}", tokenResponse.getAccessToken()))
                .onErrorMap(ex -> {
                    log.debug("Error refreshing token for session: {} ", sessionId, ex);
                    return new TokenRefreshError();
                });
    }

    public Mono<Void> revokeToken(Token token) {
        return webClient.post()
                .uri(getWellKnownConfiguration().getRevocationEndpoint())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(BodyInserters.fromFormData(OidcRequestFactory.createRevokeTokenRequestBody(
                        applicationConfiguration.getClientId(),
                        applicationConfiguration.getClientSecret(),
                        token.getRefreshToken()
                )))
                .retrieve()
                .bodyToMono(Void.class);
    }

    public boolean tokenIsValid(Token token) {
        try {
            DecodedJWT jwt = JWT.decode(token.getAccessToken());
            Algorithm algorithm = none();

            if (applicationConfiguration.isVerifyTokenSignature()) {
                Key key = jwk.getKeyById(jwt.getKeyId()).orElseThrow();
                algorithm = RSA256((RSAPublicKey) key.getPublicKey(), null);
            }
            algorithm.verify(jwt);
            log.debug("Token is valid!");
            return true;

        } catch (SignatureVerificationException | InvalidPublicKeyException e) {
            log.debug("Token is not valid!");
            log.warn("{}", e.toString());
            return false;
        }
    }


    public void fetchWellKnowConfiguration() {
        log.info("Retrieving well know OpenId configuration...");
        wellKnownConfiguration = webClient
                .get()
                .uri(applicationConfiguration.getIssuerUri().pathSegment(WELL_KNOWN_OPENID_CONFIGURATION_PATH).build().toUri())
                .retrieve()
                .bodyToMono(WellKnownConfiguration.class)
                .block();

        log.debug("Got well know OpenId configuration:");
        log.debug(wellKnownConfiguration.toString());
    }

    public void fetchJwks() {
        log.info("Retrieving JWKs...");
        jwk = webClient.get()
                .uri(wellKnownConfiguration.getJwksUri())
                .retrieve()
                .bodyToMono(Jwk.class)
                .block();
        log.debug("Got JWKs:");
        log.debug(jwk.toString());
    }

    public URI getAuthorizationUri(HttpHeaders headers) {
        var codeVerifier = PkceUtil.generateCodeVerifier();
        var state = RandomStringUtils.secureStrong().nextAlphabetic(32);
        log.debug("Generating authorization URI");

        codeVerifierCache.storeCodeVerifier(state, codeVerifier);
        return oidcRequestFactory
                .createAuthorizationUri(wellKnownConfiguration.getAuthorizationEndpoint(), headers, state, codeVerifier);

    }

    public URI getRedirectAfterLoginUri(HttpHeaders headers) {
        return oidcRequestFactory.createRedirectAfterLoginUri(headers);
    }

    public URI getRedirectAfterLogoutUri() {
        return oidcRequestFactory.createRedirectAfterLogoutUri();
    }

    public boolean tokenNeedsRefresh(Session session) {
        Duration between = Duration.between(LocalDateTime.now(), session.getTokenExpiresAt());
        log.debug("Token is expiring in {} seconds", between.toSeconds());

        return between.getSeconds() <= applicationConfiguration.getSecondsBeforeTokenRefresh();
    }
}
