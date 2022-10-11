package no.fintlabs;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
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

import static com.auth0.jwt.algorithms.Algorithm.RSA256;

@Slf4j
@Service
public class OicdService {

    public static final String WELL_KNOWN_OPENID_CONFIGURATION_PATH = ".well-known/openid-configuration";
    public static final String X_FORWARDED_PROTO = "x-forwarded-proto";
    public static final String X_FORWARDED_PORT = "x-forwarded-port";
    public static final String X_FORWARDED_HOST = "x-forwarded-host";
    private final OicdConfiguration oicdConfiguration;
    private final WebClient webClient;

    private final SessionRepository sessionRepository;
    @Getter
    private WellKnownConfiguration wellKnownConfiguration;

    private Jwk jwk;

    public OicdService(OicdConfiguration oicdConfiguration, WebClient webClient, SessionRepository sessionRepository) {
        this.oicdConfiguration = oicdConfiguration;
        this.webClient = webClient;
        this.sessionRepository = sessionRepository;
    }

    @PostConstruct
    public void init() {
        getWellKnowConfiguration();
    }

    public Mono<Token> fetchToken(Map<String, String> params, Map<String, String> headers) {
        return webClient.post()
                .uri(getWellKnownConfiguration().getTokenEndpoint() + "?resourceServer=fint-api")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(BodyInserters
                        .fromFormData("grant_type", "authorization_code")
                        .with("client_id", oicdConfiguration.getClientId())
                        .with("client_secret", oicdConfiguration.getClientSecret())
                        .with("code", params.get("code"))
                        .with("redirect_uri", createRedirectUri(headers))
                )
                .retrieve()
                .bodyToMono(Token.class)
                .map(token -> {
                    log.debug("Got token:");
                    log.debug(token.toString());
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
                .uri(oicdConfiguration.getIssuerUri().pathSegment(WELL_KNOWN_OPENID_CONFIGURATION_PATH).build().toUri())
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

    public URI createAuthorizationUriAndSession(Map<String, String> headers) throws UnsupportedEncodingException {
        String state = RandomStringUtils.randomAlphanumeric(32);
        String codeVerifier = PkceUtil.generateCodeVerifier();

        sessionRepository.addSession(state, codeVerifier);

        return UriComponentsBuilder.fromUriString(wellKnownConfiguration.getAuthorizationEndpoint())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", createRedirectUri(headers))
                .queryParam("state", state)
                .queryParam("nonce", RandomStringUtils.randomAlphanumeric(32))
                //.queryParam("code_challenge", PkceUtil.generateCodeChallange(PkceUtil.generateCodeVerifier()))
                //        .queryParam("code_challenge_method", "S256")
                .queryParam("client_id", oicdConfiguration.getClientId())
                .queryParam("scope", String.join("+", oicdConfiguration.getScopes()))
                .build()
                .toUri();

    }

    public String createRedirectUri(Map<String, String> headers) {
        return UriComponentsBuilder.newInstance()
                .scheme(headers.get(X_FORWARDED_PROTO))
                .port((headers.get(X_FORWARDED_PORT).equalsIgnoreCase("80") || headers.get(X_FORWARDED_PORT).equalsIgnoreCase("443")) ? "" : headers.get(X_FORWARDED_PORT))
                .host(headers.get(X_FORWARDED_HOST))
                .path("/callback")
                .build()
                .toUriString();
    }

}
