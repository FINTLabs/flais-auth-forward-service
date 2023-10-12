package no.fintlabs.oidc;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import no.fintlabs.controller.MissingAuthentication;
import no.fintlabs.session.CookieService;
import no.fintlabs.session.Session;
import no.fintlabs.session.SessionService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;
import static com.auth0.jwt.algorithms.Algorithm.none;

@Slf4j
@Service
public class OidcService {

    public static final String WELL_KNOWN_OPENID_CONFIGURATION_PATH = ".well-known/openid-configuration";

    private final ApplicationConfiguration applicationConfiguration;
    private final WebClient webClient;

    private final SessionService sessionService;
    @Getter
    @Setter
    private WellKnownConfiguration wellKnownConfiguration;

    private final CookieService cookieService;

    private final OidcRequestFactory oidcRequestFactory;

    @Getter
    @Setter
    private Jwk jwk;

    public OidcService(ApplicationConfiguration applicationConfiguration, WebClient webClient, SessionService sessionService, CookieService cookieService, OidcRequestFactory oidcRequestFactory) {
        this.applicationConfiguration = applicationConfiguration;
        this.webClient = webClient;
        this.sessionService = sessionService;
        this.cookieService = cookieService;
        this.oidcRequestFactory = oidcRequestFactory;
    }

    @PostConstruct
    public void init() {
        fetchWellKnowConfiguration();
        fetchJwks();
    }

    public Mono<Token> fetchToken(Map<String, String> params, HttpHeaders headers) {
        log.debug("Fetching token from {}", getWellKnownConfiguration().getTokenEndpoint() + "?resourceServer=fint-api");
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
                                                oidcRequestFactory.createCallbackUri(headers)
                                        ))
                )
                .retrieve()
                .bodyToMono(Token.class)
                .map(token -> {
                    logToken(token);
                    sessionService.updateSession(params.get("state"), token);
                    return token;
                });
    }

    private void logToken(Token token) {
        log.debug("Got token: ...{}", token.getAccessToken()
                .substring(token.getAccessToken().length() - 15));
    }

    public void refreshToken(String state, Token token) {

        log.debug("Refreshing token...");

        // TODO: 12/10/2023 remove logging of sensitive credentials
        log.debug("clientId: {}", applicationConfiguration.getClientId());
        log.debug("clientSecret: {}", applicationConfiguration.getClientSecret());

        webClient.post()
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
                .doOnError(WebClientResponseException.class, ex -> {
                    log.error("Error occured for clientId: {}", applicationConfiguration.getClientId());
                    log.error("WebClientResponseException occurred: {}", ex.getMessage());

                    // TODO remove this when a proper solution has been found
                    // https://fintlabs.atlassian.net/browse/FFS-495
                    Runtime.getRuntime().halt(1);
                })
                .subscribe(tokenResponse -> {
                    logToken(tokenResponse);
                    tokenResponse.setRefreshToken(token.getRefreshToken());
                    sessionService.updateSession(state, tokenResponse);
                });

    }

    public void verifyToken(Token token) throws MissingAuthentication, UnableToVerifyTokenSignature {

        try {
            DecodedJWT jwt = JWT.decode(token.getAccessToken());
            Algorithm algorithm = none();

            if (applicationConfiguration.isVerifyTokenSignature()) {
                Key key = jwk.getKeyById(jwt.getKeyId()).orElseThrow();
                algorithm = RSA256((RSAPublicKey) key.getPublicKey(), null);
            }
            algorithm.verify(jwt);
            log.debug("Token is valid!");
//            else {
//                log.debug("TOKEN VERIFICATION IS DISABLED!!!!!");
//            }

        } catch (SignatureVerificationException | InvalidPublicKeyException e) {
            log.debug("Token is not valid!");
            log.warn("{}", e.toString());
            throw new UnableToVerifyTokenSignature();
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

    public Mono<Void> logout(ServerHttpResponse response, Optional<String> cookieValue) {

        cookieValue.ifPresent(s -> {
            log.debug("{} sessions in session repository before logout", sessionService.sessionCount());
            sessionService.clearSessionByCookieValue(s);
            log.debug("{} sessions in session repository after logout", sessionService.sessionCount());

            response.addCookie(cookieService.createLogoutCookie(s));

        });
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(oidcRequestFactory.createRedirectAfterLogoutUri());

        return response.setComplete();
    }

    public URI getAuthorizationUri(HttpHeaders headers, Session session) {

        return oidcRequestFactory
                .createAuthorizationUri(wellKnownConfiguration.getAuthorizationEndpoint(), headers, session);

    }

    public URI getRedirectAfterLoginUri(HttpHeaders headers) {
        return oidcRequestFactory.createRedirectAfterLoginUri(headers);
    }

    @Scheduled(cron = "${fint.sso.token-refresh-cron:0 */1 * * * *}")
    public void refreshToken() {
        List<Session> activeSessions = sessionService.getActiveSessions();
        log.debug("Checking {} active session for expiring tokens", activeSessions.size());

        // TODO: 12/10/2023 remove logging of sensitive credentials
        log.debug("clientId: {}", applicationConfiguration.getClientId());
        log.debug("clientSecret: {}", applicationConfiguration.getClientSecret());

        activeSessions
                .forEach(session -> {
                    if (tokenNeedsRefresh(session)) {
                        log.debug("Token has less than 60 seconds left. Refreshing token.");
                        refreshToken(session.getSessionId(), session.getToken());
                        log.debug("Refreshed token for UPN {}", session.getUpn());
                    } else {
                        log.debug("No need to refresh token!");
                        log.debug("Session: " + session.getSessionId());
                        log.debug("Token: " + session.getToken());
                    }
                });
    }

    public boolean tokenNeedsRefresh(Session session) {
        Duration between = Duration.between(LocalDateTime.now(), session.getTokenExpiresAt());
        log.debug("Token is expiring in {} seconds", between.toSeconds());

        return between.getSeconds() <= applicationConfiguration.getSecondsBeforeTokenRefresh();
    }
}
