package no.fintlabs;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class CookieService {
    public static final String COOKIE_NAME = "user_session";

    private final OicdConfiguration oicdConfiguration;

    private static final byte[] cookieHashKey = RandomStringUtils.randomAscii(32).getBytes();

    public CookieService(OicdConfiguration oicdConfiguration) {
        this.oicdConfiguration = oicdConfiguration;
    }

    public Optional<HttpCookie> verifyCookie(MultiValueMap<String, HttpCookie> cookies) {


        if (cookies.containsKey(COOKIE_NAME)) {
            List<HttpCookie> user_session = cookies.get(COOKIE_NAME);
            if (user_session.size() == 1) {
                HttpCookie cookie = user_session.get(0);
                if (cookieValueIsValid(cookie.getValue())) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    public ResponseCookie createCookie(Map<String, String> params, Map<String, String> headers) {

        return ResponseCookie.from(COOKIE_NAME, createCookieValue(params.get("state")))
                .domain(headers.get("x-forwarded-host"))
                .httpOnly(true)
                .sameSite("Lax")
                .maxAge(Duration.ofMinutes(oicdConfiguration.getSessionMaxAgeInMinutes()))
                .secure(headers.get("x-forwarded-proto").equalsIgnoreCase("https"))
                .path("/")
                .build();
    }

    public static String createCookieValue(String value) {
        return String.format("%s|%s", createHash(value), value);
    }

    public static String getStateFromValue(String value) {
        List<String> cookieValues = Arrays.asList(value.split("\\|"));

        return cookieValues.get(1);
    }

    private boolean cookieValueIsValid(String value) {
        String[] values = value.split("\\|");
        return createHash(values[1]).equals(values[0]);
    }

    public static String createHash(String value) {
        HmacUtils hm256 = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, cookieHashKey);

        return hm256.hmacHex(value);
    }
}
