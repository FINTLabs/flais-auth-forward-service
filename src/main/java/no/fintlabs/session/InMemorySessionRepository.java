package no.fintlabs.session;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import no.fintlabs.oidc.Token;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;


@Slf4j
@Repository
public class InMemorySessionRepository implements SessionRepository {

    private final Cache<String, Session> sessions;

    private final ApplicationConfiguration applicationConfiguration;

    public InMemorySessionRepository(ApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
        sessions = Caffeine.newBuilder()
                .expireAfterWrite(applicationConfiguration.getSessionMaxAgeInMinutes(), TimeUnit.MINUTES)
                .maximumSize(10_000)
                .build();
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

        Session session = sessions.getIfPresent(sessionId);
        if (session == null) throw new SessionNotFoundException();

        session.setToken(token);
        session.setUpn(getClaimFromtJwt(jwt, applicationConfiguration.getClaimForUpn()));
        session.setTokenExpiresAt(dateToLocalDateTime(jwt.getExpiresAt()));

        sessions.put(sessionId, session);
    }

    public void clearSessionByCookieValue(String cookieValue) {
        clearSessionBySessionId(CookieService.getSessionIdFromValue(cookieValue));
    }


    public void clearSessionBySessionId(String sessionId) {
        sessions.invalidate(sessionId);
    }

    public Optional<Session> getTokenBySessionId(String sessionId) {
        var session = sessions.getIfPresent(sessionId);
        log.debug("Session ({}) exists: {}", sessionId, session != null);
        return Optional.ofNullable(session);
    }

    public Collection<Session> getSessions() {
        return sessions.asMap().values();
    }

    private String getClaimFromtJwt(DecodedJWT jwt, String claim) {
        if (jwt.getClaims().get(claim) == null) {
            jwt.getClaims().forEach((k, v) -> log.debug("Claim: {}", k));
            throw new ClaimNotFoundException("Claim " + claim + " not found in JWT");
        }

        return jwt.getClaims().get(claim).asString();
    }
}
