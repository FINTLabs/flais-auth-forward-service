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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.Map;

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
    public ResponseEntity<Void> auth(@RequestHeader Map<String, String> headers, HttpServletRequest request) throws UnsupportedEncodingException {
        log.info("Request headers:");
        headers.forEach((s, s2) -> log.info("\t{}: {}", s, s2));

        try {

            Cookie cookie = cookieService.verifyCookie(request.getCookies()).orElseThrow(MissingAuthentication::new);
            Session session = sessionRepository.getTokenByState(CookieService.getStateFromValue(cookie.getValue())).orElseThrow(MissingAuthentication::new);
            oicdService.verifyToken(session.getToken());

            return ResponseEntity
                    .ok()
                    .header(HttpHeaders.AUTHORIZATION,
                            String.format("%s %s",
                                    StringUtils.capitalize(session.getToken().getTokenType()),
                                    session.getToken().getAccessToken()
                            )
                    )
                    .build();
            //response.getHeaders().add(HttpHeaders.AUTHORIZATION, String.format("%s %s", StringUtils.capitalize(session.getToken().getTokenType()), session.getToken().getAccessToken()));
            //response.setStatusCode(HttpStatus.OK);
        } catch (MissingAuthentication e) {
            return ResponseEntity
                    .status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, oicdService.createAuthorizationUriAndSession(headers))
                    .build();
            //response.setStatusCode(HttpStatus.FOUND);
            //response.getHeaders().setLocation(oicdService.createAuthorizationUriAndSession(headers));
        }

        //return response.setComplete();

    }


    @GetMapping("callback")
    public ResponseEntity<Void> callback(@RequestParam Map<String, String> params, @RequestHeader Map<String, String> headers) {
        log.info("");

        oicdService.fetchToken(params, headers);

        return ResponseEntity
                .status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, UriComponentsBuilder.newInstance()
                        .scheme(headers.get("x-forwarded-proto"))
                        .port((headers.get("x-forwarded-port").equalsIgnoreCase("80") || headers.get("x-forwarded-port").equalsIgnoreCase("443")) ? "" : headers.get("x-forwarded-port"))
                        .host(headers.get("x-forwarded-host"))
                        .path("/auth")
                        .build()
                        .toUriString()
                )
                .header(HttpHeaders.SET_COOKIE, cookieService.createCookie(params, headers).toString())
                .build();
//        return oicdService.getToken(params, headers)
//                .flatMap(token -> {
//                    response.setStatusCode(HttpStatus.FOUND);
//                    response.getHeaders().setLocation(
//                            UriComponentsBuilder.newInstance()
//                                    .scheme(headers.get("x-forwarded-proto"))
//                                    .port((headers.get("x-forwarded-port").equalsIgnoreCase("80") || headers.get("x-forwarded-port").equalsIgnoreCase("443")) ? "" : headers.get("x-forwarded-port"))
//                                    .host(headers.get("x-forwarded-host"))
//                                    .path("/auth")
//                                    .build()
//                                    .toUri()
//                    );
//
//                    response.addCookie(cookieService.createCookie(params, headers));
//                    return response.setComplete();
//                });


        // return response.setComplete();
    }

    @GetMapping("sessions")
    public ResponseEntity<Collection<Session>> getAutenticatedUser() {
        return ResponseEntity.ok(sessionRepository.getSessions());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> onExceptionDeny() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
}
