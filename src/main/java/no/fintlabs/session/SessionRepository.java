package no.fintlabs.session;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import no.fintlabs.oidc.Token;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
@Repository
public class SessionRepository {
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public void addSession(String sessionId, String codeVerifier) {

        Session session = Session.builder()
                .codeVerifier(codeVerifier)
                .build();

        sessions.put(sessionId, session);
    }

    public void updateSession(String sessionId, Token token) {
        DecodedJWT jwt = JWT.decode(token.getAccessToken());

        Session session = sessions.get(sessionId);
        session.setToken(token);
        session.setUpn(jwt.getClaims().get("email").asString());
        session.setExpires(dateToLocalDateTime(jwt.getExpiresAt()));

        sessions.put(sessionId, session);
    }

    public void clearSession(String sessionId) {

        sessions.remove(CookieService.getStateFromValue(sessionId));
    }

    public Optional<Session> getTokenBySessionId(String sessionId) {
        log.debug("Session ({}) with exists: {}", sessionId, sessions.containsKey(sessionId));
        return Optional.ofNullable(sessions.get(sessionId));
    }

    public Collection<Session> getSessions() {
        return sessions.values();
    }

    private LocalDateTime dateToLocalDateTime(Date dateToConvert) {
        return dateToConvert.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }
}
