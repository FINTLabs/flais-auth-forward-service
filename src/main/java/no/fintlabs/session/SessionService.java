package no.fintlabs.session;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import no.fintlabs.controller.MissingAuthentication;
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
import java.util.Optional;

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

    public Optional<Session> getSessionByCookieValue(String cookieValue) {
        return sessionRepository.getTokenBySessionId(CookieService.getSessionIdFromValue(cookieValue));
    }

    public int sessionCount() {
        return sessionRepository.getSessions().size();
    }

    public Session verifySession(String sessionId) throws MissingAuthentication {
        return sessionRepository.getTokenBySessionId(CookieService.getSessionIdFromValue(sessionId))
                .orElseThrow(MissingAuthentication::new);
    }

    @Scheduled(cron = "${fint.sso.old-sessions-cleanup-cron:0 */1 * * * *}")
    public void cleanupOldSessions() {
        List<Session> oldSessions = getNonActiveSessions();

        log.debug("{} old sessions to cleanup", oldSessions.size());

        oldSessions.forEach(session -> clearSessionBySessionId(session.getSessionId()));
    }

    public List<Session> getNonActiveSessions() {
        return sessionRepository
                .getSessions()
                .stream()
                .filter(this::sessionIsNotActive
//                        session -> {
//                    Duration duration = Duration.between(LocalDateTime.now(), session.getSessionStartAt().plusMinutes(configuration.getSessionMaxAgeInMinutes()));
//                    return duration.toMinutes() <= 60;
//                }
                )
                .toList();
    }

    public List<Session> getActiveSessions() {
        return getSessions()
                .stream()
                .filter(session -> session.getUpn() != null)
                .filter(this::isSessionActive)
                .toList();
    }

    public boolean isSessionActive(Session session) {

        //if (ObjectUtils.isNotEmpty(session.getToken())) {
        return getMinutesLeftOfSession(session) > 0;
        //}

        //return false;
    }

    public boolean sessionIsNotActive(Session session) {
        return !isSessionActive(session);
    }

    private long getMinutesLeftOfSession(Session session) {
        return Duration
                .between(
                        LocalDateTime.now(),
                        session.getSessionStartAt().plusMinutes(configuration.getSessionMaxAgeInMinutes())
                )
                .toMinutes();
    }
}
