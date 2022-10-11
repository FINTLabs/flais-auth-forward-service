package no.fintlabs;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.oidc.OidcService;
import no.fintlabs.session.CookieService;
import no.fintlabs.session.Session;
import no.fintlabs.session.SessionRepository;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import static no.fintlabs.session.CookieService.COOKIE_NAME;

@Slf4j
@RestController
@RequestMapping("_oauth")
public class AuthController {

    private final OidcService oidcService;

    private final SessionRepository sessionRepository;

    private final CookieService cookieService;

    public AuthController(OidcService oidcService, SessionRepository sessionRepository, CookieService cookieService) {
        this.oidcService = oidcService;
        this.sessionRepository = sessionRepository;
        this.cookieService = cookieService;
    }

    @GetMapping
    public Mono<Void> auth(@RequestHeader HttpHeaders headers,
                           ServerHttpResponse response,
                           ServerHttpRequest request) throws UnsupportedEncodingException {
        log.debug("Hitting /auth");
        log.debug("Request headers:");
        headers.forEach((s, s2) -> log.debug("\t{}: {}", s, s2));

        try {

            HttpCookie cookie = cookieService.verifyCookie(request.getCookies()).orElseThrow(MissingAuthentication::new);
            Session session = sessionRepository.getTokenByState(CookieService.getStateFromValue(cookie.getValue())).orElseThrow(MissingAuthentication::new);
            oidcService.verifyToken(session.getToken());

            URI forwardTo = URI.create(Optional.ofNullable(headers.getFirst("X-Forwarded-Uri")).orElse("/"));
            log.debug("Authentication is ok!");
            log.debug("Redirecting to {}", forwardTo);
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(forwardTo);
            response.getHeaders().add(HttpHeaders.AUTHORIZATION, String.format("%s %s", StringUtils.capitalize(session.getToken().getTokenType()), session.getToken().getAccessToken()));
        } catch (MissingAuthentication e) {
            URI authorizationUri = oidcService.createAuthorizationUriAndSession(headers);
            log.debug("Missing authentication!");
            log.debug("Redirecting to {}", authorizationUri);
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(authorizationUri);
            Optional.ofNullable(headers.getFirst("X-Forwarded-Uri")).ifPresent(s -> response.getHeaders().set("X-Forwarded-Uri", s));
        }

        return response.setComplete();

    }


    @GetMapping("callback")
    public Mono<Void> callback(@RequestParam Map<String, String> params,
                               @RequestHeader HttpHeaders headers,
                               ServerHttpResponse response) {

        log.debug("Hitting /callback");
        log.debug("Request headers:");
        headers.forEach((s, s2) -> log.debug("\t{}: {}", s, s2));
        log.debug("Request parameters:");
        params.forEach((s, s2) -> log.debug("\t{}: {}", s, s2));

        return oidcService.fetchToken(params, headers)
                .flatMap(token -> {

                    URI authUri = UriComponentsBuilder.newInstance()
                            .scheme(oidcService.getProtocol(headers))
                            .port(oidcService.getPort(headers))
                            .host(headers.getFirst("x-forwarded-host"))
                            .path("/_oauth")
                            .build()
                            .toUri();

                    log.debug("Redirecting to {}", authUri);
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(authUri);

                    response.addCookie(cookieService.createAuthenticationCookie(params));
                    return response.setComplete();
                });
    }

    @GetMapping("logout")
    public Mono<Void> logout(@CookieValue(value = COOKIE_NAME, required = false) Optional<String> cookieValue, ServerHttpResponse response) {
        return oidcService.logout(response, cookieValue);
    }

    @GetMapping("sessions")
    public Mono<Collection<Session>> getAutenticatedUser() {
        return Mono.just(sessionRepository.getSessions());
    }

    @GetMapping("test")
    public Mono<String> test() {
        return Mono.just("Hello world!");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> onExceptionDeny(Exception e) {
        log.debug(e.toString());
        e.printStackTrace();
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}
