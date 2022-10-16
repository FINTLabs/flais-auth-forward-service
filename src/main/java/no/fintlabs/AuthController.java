package no.fintlabs;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.oidc.OidcRequestFactory;
import no.fintlabs.oidc.OidcService;
import no.fintlabs.session.CookieService;
import no.fintlabs.session.Session;
import no.fintlabs.session.ConcurrentHashMapSessionRepository;
import no.fintlabs.session.SessionService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
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
    private final OidcRequestFactory oidcRequestFactory;

    private final ConcurrentHashMapSessionRepository concurrentHashMapSessionRepository;

    private final CookieService cookieService;

    private final SessionService sessionService;


    public AuthController(OidcService oidcService, ConcurrentHashMapSessionRepository concurrentHashMapSessionRepository, CookieService cookieService, OidcRequestFactory oidcRequestFactory, SessionService sessionService) {
        this.oidcService = oidcService;
        this.concurrentHashMapSessionRepository = concurrentHashMapSessionRepository;
        this.cookieService = cookieService;
        this.oidcRequestFactory = oidcRequestFactory;
        this.sessionService = sessionService;
    }

    @GetMapping
    public Mono<Void> oauth(@CookieValue(value = COOKIE_NAME, required = false) Optional<String> cookieValue,
                            @RequestHeader HttpHeaders headers,
                            ServerHttpResponse response,
                            ServerHttpRequest request) throws UnsupportedEncodingException {

        log.debug("Calling {}", request.getPath());
        logForwardedHeaders(headers);

        try {

            String verifiedCookieValue = cookieService.verifyCookie(cookieValue);
            Session session = sessionService.verifySession(verifiedCookieValue);
            oidcService.verifyToken(session.getToken());

            log.debug("Authentication is ok!");
            response.setStatusCode(HttpStatus.OK);
            response.getHeaders().add(HttpHeaders.AUTHORIZATION, String.format("%s %s", StringUtils.capitalize(session.getToken().getTokenType()), session.getToken().getAccessToken()));

        } catch (MissingAuthentication e) {

            Session session = sessionService.initializeSession();
            URI authorizationUri = oidcService.createAuthorizationUri(headers, session);
            log.debug("Missing authentication!");
            log.debug("Redirecting to {}", authorizationUri);
            response.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
            response.getHeaders().setLocation(authorizationUri);
        }

        return response.setComplete();
    }

    @GetMapping("callback")
    public Mono<Void> callback(@RequestParam Map<String, String> queryParameters,
                               @RequestHeader HttpHeaders headers,
                               ServerHttpResponse response,
                               ServerHttpRequest request) {

        log.debug("Calling {}", request.getPath());
        logForwardedHeaders(headers);
        log.debug("Request parameters:");
        queryParameters.forEach((s, s2) -> log.debug("\t{}: {}", s, s2));

        return oidcService.fetchToken(queryParameters, headers)
                .flatMap(token -> {

                    response.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
                    response.getHeaders().setLocation(oidcRequestFactory.createRedirectAfterLoginUri(headers));
                    response.addCookie(cookieService.createAuthenticationCookie(queryParameters));

                    return response.setComplete();
                });
    }

    @GetMapping("logout")
    public Mono<Void> logout(@CookieValue(value = COOKIE_NAME, required = false) Optional<String> cookieValue,
                             ServerHttpResponse response,
                             ServerHttpRequest request) {

        log.debug("Calling {}", request.getPath());

        return oidcService.logout(response, cookieValue);
    }



    @GetMapping("sessions")
    public Mono<Collection<Session>> getAutenticatedUser(ServerHttpRequest request) {

        log.debug("Calling {}", request.getPath());

        return Mono.just(concurrentHashMapSessionRepository.getSessions());
    }

    @GetMapping("test")
    public Mono<String> test(ServerHttpRequest request) {

        log.debug("Calling {}", request.getPath());

        return Mono.just("Greetings from FINTLabs!");
    }

    private void logForwardedHeaders(HttpHeaders headers) {
        log.debug("X-Forwarded headers:");
        headers.forEach((s, s2) -> {
            if (s.toLowerCase().startsWith("x-forwarded")) {
                log.debug("\t{}: {}", s, s2);
            }
        });
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> onExceptionDeny(Exception e) {
        log.debug(e.toString());
        e.printStackTrace();
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}
