package no.fintlabs.controller;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.oidc.OidcService;
import no.fintlabs.oidc.UnableToVerifyTokenSignature;
import no.fintlabs.session.CookieService;
import no.fintlabs.session.Session;
import no.fintlabs.session.SessionNotFoundException;
import no.fintlabs.session.SessionService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;

import static no.fintlabs.session.CookieService.COOKIE_NAME;

@Slf4j
@RestController
@RequestMapping("_oauth")
public class AuthController {
    private final OidcService oidcService;
    private final CookieService cookieService;
    private final SessionService sessionService;

    public AuthController(OidcService oidcService, CookieService cookieService, SessionService sessionService) {
        this.oidcService = oidcService;
        this.cookieService = cookieService;
        this.sessionService = sessionService;
    }

    @GetMapping
    public Mono<Void> oauth(
            @CookieValue(value = COOKIE_NAME, required = false) Optional<String> cookieValue,
            @RequestHeader HttpHeaders headers,
            ServerHttpResponse response,
            ServerHttpRequest request) {

        if (log.isDebugEnabled()) logRequest(request);

        return cookieValue
                .map(cookieService::getSessionId)
                .orElse(Mono.error(new MissingAuthenticationCookie()))
                .flatMap(sessionService::getSession)
                .flatMap(session -> oidcService.tokenIsValid(session.getToken())
                        ? Mono.just(session)
                        : Mono.error(new UnableToVerifyTokenSignature()))
                .flatMap(session -> oidcService.tokenNeedsRefresh(session)
                        ? handleTokenRefresh(session, response)
                        : Mono.just(session))
                .flatMap(session -> {
                    var token = session.getToken();
                    var authHeader = String.format("%s %s",
                            StringUtils.capitalize(token.getTokenType()), token.getAccessToken());
                    response.getHeaders().add(HttpHeaders.AUTHORIZATION, authHeader);
                    response.setStatusCode(HttpStatus.OK);
                    return response.setComplete();
                })
                .onErrorResume(e -> {
                    if (e instanceof SecurityException) {
                        try {
                            cookieValue.ifPresent(sessionService::clearSessionByCookieValue);
                        } catch (Exception ignored) {}

                        var session = sessionService.initializeSession();
                        var redirectUri = oidcService.getAuthorizationUri(headers, session);

                        log.debug("Missing authentication!");
                        log.debug("Redirecting to {}", redirectUri);

                        response.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
                        response.getHeaders().setLocation(redirectUri);

                        return response.setComplete();
                    }
                    return Mono.error(e);
                });
    }

    private Mono<Session> handleTokenRefresh(Session session, ServerHttpResponse response) {
        return oidcService.refreshToken(session.getSessionId(), session.getToken())
                .flatMap(refreshedToken -> {
                    refreshedToken.setRefreshToken(session.getToken().getRefreshToken());
                    response.addCookie(cookieService.createAuthenticationCookie(
                            session.getSessionId(), refreshedToken.getExpiresIn()));
                    return Mono.just(sessionService.updateSession(session.getSessionId(), refreshedToken));
                }).onErrorMap(SessionNotFoundException.class, e -> new MissingSession());
    }

    @GetMapping("callback")
    public Mono<Void> callback(@RequestParam Map<String, String> queryParameters,
                               @RequestHeader HttpHeaders headers,
                               ServerHttpResponse response,
                               ServerHttpRequest request) {

        if (log.isDebugEnabled()) logRequest(request);

        return oidcService.fetchToken(queryParameters, headers)
                .flatMap(token -> {
                    sessionService.updateSession(queryParameters.get("state"), token);
                    response.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
                    response.getHeaders().setLocation(oidcService.getRedirectAfterLoginUri(headers));
                    response.addCookie(cookieService.createAuthenticationCookie(queryParameters.get("state"), token.getExpiresIn()));

                    return response.setComplete();
                });
    }

    @GetMapping("logout")
    public Mono<Void> logout(@CookieValue(value = COOKIE_NAME, required = false) Optional<String> cookieValue,
                             ServerHttpResponse response,
                             ServerHttpRequest request) {

        log.debug("Calling {}", request.getPath());

        return Mono.justOrEmpty(cookieValue)
                .flatMap(cookie ->
                        cookieService.getSessionId(cookie)
                                .flatMap(sessionService::getSession)
                                .flatMap(session -> {
                                    // Clear the session and set cookies
                                    sessionService.clearSessionBySessionId(session.getSessionId());
                                    response.addCookie(cookieService.createRemoveAuthenticationCookie());
                                    response.addCookie(cookieService.createLogoutCookie(cookie));

                                    // Revoke the token, but continue regardless of errors
                                    return oidcService.revokeToken(session.getToken())
                                            .onErrorResume(e -> {
                                                log.error("Error revoking token: {}", e.getMessage());
                                                return Mono.empty();
                                            });
                                })
                )
                .then(Mono.defer(() -> {
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(oidcService.getRedirectAfterLogoutUri());
                    return response.setComplete();
                }));
    }

    @GetMapping("sessions/me")
    public Mono<Session> getUserSession(
            @CookieValue(value = COOKIE_NAME, required = false) Optional<String> cookieValue,
            ServerHttpRequest request) {

        log.debug("Calling {}", request.getPath());
        return cookieValue
                .map(cookieService::getSessionId)
                .orElse(Mono.error(new MissingAuthenticationCookie()))
                .flatMap(sessionService::getSession);
    }

    private void logRequest(ServerHttpRequest request) {
        log.debug("Calling {}", request.getPath());

        log.debug("X-Forwarded headers:");
        request.getHeaders().forEach((s, s2) -> {
            if (s.toLowerCase().startsWith("x-forwarded")) {
                log.debug("\t{}: {}", s, s2);
            }
        });

        log.debug("Request parameters:");
        request.getQueryParams().forEach((s, s2) -> log.debug("\t{}: {}", s, s2));
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<Void> handleSecurityException(SecurityException e) {
        log.debug(e.toString());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> handleException(Exception e) {
        log.debug(e.toString());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}
