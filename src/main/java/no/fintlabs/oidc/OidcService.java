package no.fintlabs.oidc;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import no.fintlabs.MissingAuthentication;
import no.fintlabs.session.CookieService;
import no.fintlabs.session.Session;
import no.fintlabs.session.SessionRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;

@Slf4j
@Service
public class OidcService {

    public static final String WELL_KNOWN_OPENID_CONFIGURATION_PATH = ".well-known/openid-configuration";

    private final OidcConfiguration oidcConfiguration;
    private final WebClient webClient;

    private final SessionRepository sessionRepository;
    @Getter
    private WellKnownConfiguration wellKnownConfiguration;

    private final CookieService cookieService;

    private final OidcRequestFactory oidcRequestFactory;

    @Getter
    private Jwk jwk;

    public OidcService(OidcConfiguration oidcConfiguration, WebClient webClient, SessionRepository sessionRepository, CookieService cookieService, OidcRequestFactory oidcRequestFactory) {
        this.oidcConfiguration = oidcConfiguration;
        this.webClient = webClient;
        this.sessionRepository = sessionRepository;
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
                                                oidcConfiguration.getClientId(),
                                                oidcConfiguration.getClientSecret(),
                                                params.get("code"),
                                                oidcRequestFactory.createCallbackUri(headers)
                                        ))
                )
                .retrieve()
                .bodyToMono(Token.class)
                .map(token -> {
                    log.debug("Got token: {}", token.toString());
                    sessionRepository.updateSession(params.get("state"), token);
                    return token;
                });
    }

    public void verifyToken(Token token) throws MissingAuthentication {

        try {
            DecodedJWT jwt = JWT.decode(token.getAccessToken());
            Key key = jwk.getKeyById(jwt.getKeyId()).orElseThrow();
            Algorithm algorithm = RSA256((RSAPublicKey) key.getPublicKey(), null);
            algorithm.verify(jwt);
            log.debug("Token is valid!");
        } catch (SignatureVerificationException | InvalidPublicKeyException e) {
            log.debug("Token is valid!");
            log.warn("{}", e.toString());
            throw new MissingAuthentication();
        }
    }


    public void fetchWellKnowConfiguration() {
        log.info("Retrieving well know OpenId configuration...");
        wellKnownConfiguration = webClient
                .get()
                .uri(oidcConfiguration.getIssuerUri().pathSegment(WELL_KNOWN_OPENID_CONFIGURATION_PATH).build().toUri())
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
            log.debug("{} sessions in session repository before logout", sessionRepository.getSessions().size());
            sessionRepository.clearSession(s);
            log.debug("{} sessions in session repository after logout", sessionRepository.getSessions().size());

            response.addCookie(cookieService.createLogoutCookie(s));

        });
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(oidcConfiguration.getRedirectAfterLogoutUri());

        return response.setComplete();
    }

    public URI createAuthorizationUri(HttpHeaders headers, Session session) throws UnsupportedEncodingException {

        return oidcRequestFactory
                .createAuthorizationUri(wellKnownConfiguration.getAuthorizationEndpoint(), headers, session);

    }


}
