package no.fintlabs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class SessionRepository {
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public void addSession(String state, String codeVerifier) {
        //DecodedJWT jwt = JWT.decode(token.getAccessToken());

        Session session = Session.builder()
                //.upn(jwt.getClaims().get("email").asString())
                //.expires(jwt.getExpiresAt())
                //.token(token)
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
        return Optional.ofNullable(sessions.get(state));
    }

    public Collection<Session> getSessions() {
        return sessions.values();
    }
}
