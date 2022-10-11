package no.fintlabs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
@Repository
public class SessionRepository {
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public void addSession(String state, String codeVerifier) {

        Session session = Session.builder()
                .codeVerifier(codeVerifier)
                .build();

        sessions.put(state, session);
    }

    public void updateSession(String state, Token token) {
        DecodedJWT jwt = JWT.decode(token.getAccessToken());

        Session session = sessions.get(state);
        session.setToken(token);
        session.setUpn(jwt.getClaims().get("email").asString());
        session.setExpires(jwt.getExpiresAt());

        sessions.put(state, session);
    }

    public void clearToken(String state) {
        sessions.remove(state);
    }

    public Optional<Session> getTokenByState(String state) {
        log.debug("Session ({}) with exists: {}", state, sessions.containsKey(state));
        return Optional.ofNullable(sessions.get(state));
    }

    public Collection<Session> getSessions() {
        return sessions.values();
    }
}
