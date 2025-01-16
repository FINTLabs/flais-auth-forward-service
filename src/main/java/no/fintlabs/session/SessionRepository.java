package no.fintlabs.session;

import no.fintlabs.oidc.Token;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;

public interface SessionRepository {

    //Session addSession(String sessionId, String codeVerifier);
    Session addSession(String sessionId, Token token);
    Session updateSession(String sessionId, Token token);
    void clearSessionByCookieValue(String cookieValue);
    void clearSessionBySessionId(String sessionId);
    Optional<Session> getTokenBySessionId(String sessionId);
    Collection<Session> getSessions();

    default LocalDateTime dateToLocalDateTime(Date dateToConvert) {
        return dateToConvert.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }
}
