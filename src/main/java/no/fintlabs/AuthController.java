package no.fintlabs;

import lombok.extern.slf4j.Slf4j;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RestController
@RequestMapping("_oauth")
public class AuthController {

    private final OicdService oicdService;

    private final SessionRepository sessionRepository;

    private final CookieService cookieService;

    public AuthController(OicdService oicdService, SessionRepository sessionRepository, CookieService cookieService) {
        this.oicdService = oicdService;
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
            oicdService.verifyToken(session.getToken());

            URI xForwardedUri = URI.create(Objects.requireNonNull(headers.getFirst("X-Forwarded-Uri")));
            log.debug("Authentication is ok!");
            log.debug("Redirecting to {}", xForwardedUri);
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(URI.create(Objects.requireNonNull(headers.getFirst("X-Forwarded-Uri"))));
            response.getHeaders().add(HttpHeaders.AUTHORIZATION, String.format("%s %s", StringUtils.capitalize(session.getToken().getTokenType()), session.getToken().getAccessToken()));
        } catch (MissingAuthentication e) {
            URI authorizationUri = oicdService.createAuthorizationUriAndSession(headers);
            log.debug("Missing authentication!");
            log.debug("Redirecting to {}", authorizationUri);
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(authorizationUri);
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

        return oicdService.fetchToken(params, headers)
                .flatMap(token -> {

                    URI authUri = UriComponentsBuilder.newInstance()
                            .scheme(oicdService.getProtocol(headers))
                            .port(oicdService.getPort(headers))
                            .host(headers.getFirst("x-forwarded-host"))
                            .path("/auth")
                            .build()
                            .toUri();

                    log.debug("Redirecting to {}", authUri);
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(authUri);

                    response.addCookie(cookieService.createCookie(params, headers));
                    return response.setComplete();
                });
    }

    @GetMapping("sessions")
    public Mono<Collection<Session>> getAutenticatedUser() {
        return Mono.just(sessionRepository.getSessions());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> onExceptionDeny(Exception e) {
        log.debug(e.toString());
         e.printStackTrace();
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}
