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
import no.fintlabs.session.SessionRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;
import static no.fintlabs.Headers.*;

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

    private Jwk jwk;

    public OidcService(OidcConfiguration oidcConfiguration, WebClient webClient, SessionRepository sessionRepository, CookieService cookieService) {
        this.oidcConfiguration = oidcConfiguration;
        this.webClient = webClient;
        this.sessionRepository = sessionRepository;
        this.cookieService = cookieService;
    }

    @PostConstruct
    public void init() {
        getWellKnowConfiguration();
    }

    public Mono<Token> fetchToken(Map<String, String> params, HttpHeaders headers) {
        log.debug("Fetching token from {}", getWellKnownConfiguration().getTokenEndpoint() + "?resourceServer=fint-api");
        return webClient.post()
                .uri(getWellKnownConfiguration().getTokenEndpoint() + "?resourceServer=fint-api")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(BodyInserters
                        .fromFormData("grant_type", "authorization_code")
                        .with("client_id", oidcConfiguration.getClientId())
                        .with("client_secret", oidcConfiguration.getClientSecret())
                        .with("code", params.get("code"))
                        .with("redirect_uri", createCallbackUri(headers))
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
        } catch (SignatureVerificationException | InvalidPublicKeyException e) {
            log.warn("{}", e.toString());
            throw new MissingAuthentication();
        }
    }

    private void getWellKnowConfiguration() {
        log.info("Retrieving well know OpenId configuration...");
        webClient
                .get()
                .uri(oidcConfiguration.getIssuerUri().pathSegment(WELL_KNOWN_OPENID_CONFIGURATION_PATH).build().toUri())
                .retrieve()
                .bodyToMono(WellKnownConfiguration.class)
                .subscribe(configuration -> {
                    log.debug("Got well know OpenId configuration:");
                    log.debug(configuration.toString());
                    wellKnownConfiguration = configuration;
                    getJwks();
                });
    }

    private void getJwks() {
        log.info("Retrieving JWKs...");
        webClient.get()
                .uri(wellKnownConfiguration.getJwksUri())
                .retrieve()
                .bodyToMono(Jwk.class)
                .subscribe(jwks -> {
                    log.debug("Got JWKs:");
                    log.debug(jwks.toString());
                    jwk = jwks;
                });
    }

    public Mono<Void> logout(ServerHttpResponse response, Optional<String> cookieValue) {

        cookieValue.ifPresent(s -> {
            log.debug("{} sessions in session repository before logout", sessionRepository.getSessions().size());
            sessionRepository.clearSession(s);
            log.debug("{} sessions in session repository after logout", sessionRepository.getSessions().size());

            response.addCookie(cookieService.createLogoutCookie(s));

        });
        response.setStatusCode(HttpStatus.FOUND);
        //response.getHeaders().setLocation(oicdConfiguration.getRedirectAfterLogoutUri());

        return response.setComplete();
    }

    public URI createAuthorizationUriAndSession(HttpHeaders headers) throws UnsupportedEncodingException {
        String state = RandomStringUtils.randomAlphanumeric(32);
        String codeVerifier = PkceUtil.generateCodeVerifier();

        sessionRepository.addSession(state, codeVerifier);

        return UriComponentsBuilder.fromUriString(wellKnownConfiguration.getAuthorizationEndpoint())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", createCallbackUri(headers))
                .queryParam("state", state)
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
                .path("/_oauth/callback")
                .build()
                .toUriString();
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
