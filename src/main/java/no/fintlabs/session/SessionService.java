package no.fintlabs.session;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.controller.MissingSession;
import no.fintlabs.oidc.Token;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
public class SessionService {

    private final SessionRepository sessionRepository;

    public SessionService(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    public Session initializeSession(Token token) {
        log.debug("Initializing new session");
        String sessionId = RandomStringUtils.randomAlphanumeric(32);
        return sessionRepository.addSession(sessionId, token);
    }

    public Session updateSession(String sessionId, Token token) {
        log.debug("Updating session");
        return sessionRepository.updateSession(sessionId, token);
    }

    public void clearSessionBySessionId(String sessionId) {
        sessionRepository.clearSessionBySessionId(sessionId);
    }

    public void clearSessionByCookieValue(String cookieValue) {
        sessionRepository.clearSessionByCookieValue(cookieValue);
    }

    public int sessionCount() {
        return sessionRepository.getSessions().size();
    }

    public Mono<Session> getSession(String sessionId) {
        return sessionRepository.getTokenBySessionId(sessionId)
                .map(Mono::just)
                .orElse(Mono.error(new MissingSession()));
    }
}
