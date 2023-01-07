package no.fintlabs.session;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import no.fintlabs.MissingAuthentication;
import no.fintlabs.oidc.PkceUtil;
import no.fintlabs.oidc.Token;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Slf4j
@Service
public class SessionService {

    private final ApplicationConfiguration configuration;
    private final SessionRepository sessionRepository;

    public SessionService(ApplicationConfiguration configuration, SessionRepository sessionRepository) {
        this.configuration = configuration;
        this.sessionRepository = sessionRepository;
    }

    public Session initializeSession() throws UnsupportedEncodingException {
        return initializeSession(LocalDateTime.now());
    }

    public Session initializeSession(LocalDateTime sessionStart) throws UnsupportedEncodingException {

        log.debug("Initializing new session");
        String state = RandomStringUtils.randomAlphanumeric(32);
        String codeVerifier = PkceUtil.generateCodeVerifier();

        return sessionRepository.addSession(state, codeVerifier, sessionStart);
    }

    public void updateSession(String sessionId, Token token) {
        sessionRepository.updateSession(sessionId, token);
    }

    public void clearSessionBySessionId(String sessionId) {
        sessionRepository.clearSessionBySessionId(sessionId);
    }

    public void clearSessionByCookieValue(String cookieValue) {
        sessionRepository.clearSessionByCookieValue(cookieValue);
    }

    public Collection<Session> getSessions() {
        return sessionRepository.getSessions();
    }

    public int sessionCount() {
        return sessionRepository.getSessions().size();
    }

    public Session verifySession(String sessionId) throws MissingAuthentication {
        return sessionRepository.getTokenBySessionId(CookieService.getStateFromValue(sessionId))
                .orElseThrow(MissingAuthentication::new);
    }

    @Scheduled(cron = "*/10 * * * * *")
    public void cleanupOldSessions() {
        List<Session> oldSessions = sessionRepository
                .getSessions()
                .stream()
                .filter(session -> {
                    Duration duration = Duration.between(LocalDateTime.now(), session.getSessionStartAt().plusMinutes(configuration.getSessionMaxAgeInMinutes()));
                    return duration.toMinutes() <= 60;
                })
                .toList();

        log.debug("{} old sessions to cleanup", oldSessions.size());

        oldSessions.forEach(session -> clearSessionBySessionId(session.getSessionId()));
    }
}
