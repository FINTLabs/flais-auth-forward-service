package no.fintlabs.session;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.controller.MissingAuthentication;
import no.fintlabs.ApplicationConfiguration;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.server.Cookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class CookieService {
    public static final String COOKIE_NAME = "user_session";

    @Value("${spring.webflux.base-path:/}")
    private String basePath;

    private final ApplicationConfiguration applicationConfiguration;

    private static final byte[] cookieHashKey = RandomStringUtils.randomAscii(32).getBytes();

    public CookieService(ApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    public Mono<String> getSessionId(String value) {
        if (cookieValueIsValid(value)) {
            log.debug("Cookie is valid!");
            return Mono.just(getSessionIdFromValue(value));
        }
        log.debug("Cookie is not valid!");
        return Mono.error(new MissingAuthentication());
    }

    public ResponseCookie createAuthenticationCookie(String state, long expiresIn) {

        return ResponseCookie.from(COOKIE_NAME, createCookieValue(state))
                //.domain(headers.getFirst("x-forwarded-host"))
                .httpOnly(true)
                .sameSite("Lax")
                .maxAge(applicationConfiguration.getSessionMaxAgeInMinutes() == -1
                        ? Duration.ofSeconds(expiresIn)
                        : Duration.ofMinutes(applicationConfiguration.getSessionMaxAgeInMinutes())
                )
                .secure(applicationConfiguration.isEnforceHttps())
                .path(basePath)
                .build();
    }

    public ResponseCookie createRemoveAuthenticationCookie() {
        return ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .sameSite("Lax")
                .maxAge(0)
                .secure(applicationConfiguration.isEnforceHttps())
                .path(basePath)
                .build();
    }

    public ResponseCookie createLogoutCookie(String cookieValue) {
        return ResponseCookie.from(COOKIE_NAME, cookieValue)
                .httpOnly(true)
                .sameSite("Lax")
                .maxAge(0)
                .secure(applicationConfiguration.isEnforceHttps())
                .path("/")
                .build();
    }

    public static String createCookieValue(String value) {
        return String.format("%s.%s", createHash(value), value);
    }

    public static String getSessionIdFromValue(String value) {
        List<String> cookieValues = Arrays.asList(value.split("\\."));

        return cookieValues.get(1);
    }

    private boolean cookieValueIsValid(String value) {
        String[] values = value.split("\\.");
        boolean cookieValueIsValid = createHash(values[1]).equals(values[0]);
        log.debug("Cookie value is valid: {}", cookieValueIsValid);
        return cookieValueIsValid;
    }

    public static String createHash(String value) {
        HmacUtils hm256 = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, cookieHashKey);

        return hm256.hmacHex(value);
    }
}
