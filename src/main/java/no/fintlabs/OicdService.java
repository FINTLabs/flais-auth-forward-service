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

import javax.annotation.PostConstruct;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Objects;

import static com.auth0.jwt.algorithms.Algorithm.RSA256;

@Slf4j
@Service
public class OicdService {

    private final OicdConfiguration oicdConfiguration;
    private final WebClient webClient;

    private final SessionRepository sessionRepository;
    @Getter
    private WellKnownConfiguration wellKnownConfiguration;

    private JwkRepository jwkRepository;

    public OicdService(OicdConfiguration oicdConfiguration, WebClient webClient, SessionRepository sessionRepository) {
        this.oicdConfiguration = oicdConfiguration;
        this.webClient = webClient;
        this.sessionRepository = sessionRepository;
    }

    @PostConstruct
    public void init() {
        getWellKnowConfiguration();
    }

    public void fetchToken(Map<String, String> params, Map<String, String> headers) {
        Token token = webClient.post()
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
//                .map(token -> {
//                    log.debug(token.toString());
//                    sessionRepository.updateSession(params.get("state"), token);
//                    return token;
//                })
                .block();


        log.debug(Objects.requireNonNull(token).toString());
        sessionRepository.updateSession(params.get("state"), token);
    }

    public void verifyToken(Token token) throws MissingAuthentication {

        try {
            DecodedJWT jwt = JWT.decode(token.getAccessToken());
            Key key = jwkRepository.getKeyById(jwt.getKeyId()).orElseThrow();
            Algorithm algorithm = RSA256((RSAPublicKey) key.getPublicKey(), null);
            algorithm.verify(jwt);
        } catch (SignatureVerificationException | InvalidPublicKeyException e) {
            log.warn("{}", e.toString());
            throw new MissingAuthentication();
        }
    }

    private void getWellKnowConfiguration() {
        log.info("Retrieving well know OpenId configuration");
        webClient.get().uri("/nidp/oauth/nam/.well-known/openid-configuration")
                .retrieve()
                .bodyToMono(WellKnownConfiguration.class)
                .subscribe(configuration -> {
                    log.info("Got well know OpenId configuration:");
                    log.info(configuration.toString());
                    wellKnownConfiguration = configuration;
                    getJwks();
                });
    }

    private void getJwks() {
        log.info("Retrieving JWKs");
        webClient.get()
                .uri(wellKnownConfiguration.getJwksUri())
                .retrieve()
                .bodyToMono(JwkRepository.class)
                .subscribe(jwks -> {
                    log.info("Got JWKs:");
                    log.info(jwks.toString());
                    jwkRepository = jwks;
                });
    }

    public String createAuthorizationUriAndSession(Map<String, String> headers) throws UnsupportedEncodingException {
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
                .toUriString();

    }

    public String createRedirectUri(Map<String, String> headers) {
        return UriComponentsBuilder.newInstance()
                .scheme(headers.get("x-forwarded-proto"))
                .port((headers.get("x-forwarded-port").equalsIgnoreCase("80") || headers.get("x-forwarded-port").equalsIgnoreCase("443")) ? "" : headers.get("x-forwarded-port"))
                .host(headers.get("x-forwarded-host"))
                .path("/callback")
                .build()
                .toUriString();
    }
}
