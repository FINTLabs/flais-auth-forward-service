package no.fintlabs.session;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import no.fintlabs.oidc.Token;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
@Repository
public class ConcurrentHashMapSessionRepository implements SessionRepository {

    private final Map<String, Session> sessions;

    private final ApplicationConfiguration applicationConfiguration;

    public ConcurrentHashMapSessionRepository(ApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
        sessions = new ConcurrentHashMap<>();
    }

    public Session addSession(String sessionId, String codeVerifier, LocalDateTime sessionStart) {

        Session session = Session.builder()
                .codeVerifier(codeVerifier)
                .sessionId(sessionId)
                .sessionStartAt(sessionStart)
                .build();

        sessions.put(sessionId, session);

        return session;
    }

    public void updateSession(String sessionId, Token token) {
        DecodedJWT jwt = JWT.decode(token.getAccessToken());

        Session session = sessions.get(sessionId);
        session.setToken(token);
        session.setUpn(getClaimFromtJwt(jwt, applicationConfiguration.getClaimForUpn()));
        session.setTokenExpiresAt(dateToLocalDateTime(jwt.getExpiresAt()));

        sessions.put(sessionId, session);
    }

    public void clearSessionByCookieValue(String cookieValue) {
        sessions.remove(CookieService.getSessionIdFromValue(cookieValue));
    }


    public void clearSessionBySessionId(String sessionId) {
        sessions.remove(sessionId);
    }

    public Optional<Session> getTokenBySessionId(String sessionId) {
        log.debug("Session ({}) exists: {}", sessionId, sessions.containsKey(sessionId));
        return Optional.ofNullable(sessions.get(sessionId));
    }

    public Collection<Session> getSessions() {
        return sessions.values();
    }

    private String getClaimFromtJwt(DecodedJWT jwt, String claim) {
        if (jwt.getClaims().get(claim) == null) {
            jwt.getClaims().forEach((k, v) -> log.debug("Claim: {}", k));
            throw new ClaimNotFoundException("Claim " + claim + " not found in JWT");
        }

        return jwt.getClaims().get(claim).asString();
    }
}
