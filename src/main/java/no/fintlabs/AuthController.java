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
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;

@Slf4j
@RestController
public class AuthController {

    private final OicdService oicdService;

    private final SessionRepository sessionRepository;

    private final CookieService cookieService;

    public AuthController(OicdService oicdService, SessionRepository sessionRepository, CookieService cookieService) {
        this.oicdService = oicdService;
        this.sessionRepository = sessionRepository;
        this.cookieService = cookieService;
    }

    @GetMapping("auth")
    public Mono<Void> auth(@RequestHeader HttpHeaders headers,
                           ServerHttpResponse response,
                           ServerHttpRequest request) throws UnsupportedEncodingException {
        log.debug("Request headers:");
        headers.forEach((s, s2) -> log.debug("\t{}: {}", s, s2));

        try {

            HttpCookie cookie = cookieService.verifyCookie(request.getCookies()).orElseThrow(MissingAuthentication::new);
            Session session = sessionRepository.getTokenByState(CookieService.getStateFromValue(cookie.getValue())).orElseThrow(MissingAuthentication::new);
            oicdService.verifyToken(session.getToken());

            response.getHeaders().add(HttpHeaders.AUTHORIZATION, String.format("%s %s", StringUtils.capitalize(session.getToken().getTokenType()), session.getToken().getAccessToken()));
            response.setStatusCode(HttpStatus.OK);
        } catch (MissingAuthentication e) {
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(oicdService.createAuthorizationUriAndSession(headers));
        }

        return response.setComplete();

    }


    @GetMapping("callback")
    public Mono<Void> callback(@RequestParam Map<String, String> params,
                               @RequestHeader HttpHeaders headers,
                               ServerHttpResponse response) {

        return oicdService.fetchToken(params, headers)
                .flatMap(token -> {

                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(
                            UriComponentsBuilder.newInstance()
                                    .scheme(headers.getFirst("x-forwarded-proto"))
                                    .port((Objects.requireNonNull(headers.getFirst("x-forwarded-port")).equalsIgnoreCase("80") || Objects.requireNonNull(headers.getFirst("x-forwarded-port")).equalsIgnoreCase("443")) ? "" : headers.getFirst("x-forwarded-port"))
                                    .host(headers.getFirst("x-forwarded-host"))
                                    .path("/auth")
                                    .build()
                                    .toUri()
                    );

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
