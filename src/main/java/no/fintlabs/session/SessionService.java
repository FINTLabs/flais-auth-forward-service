package no.fintlabs.session;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.MissingAuthentication;
import no.fintlabs.oidc.PkceUtil;
import no.fintlabs.oidc.Token;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.util.Collection;

@Slf4j
@Service
public class SessionService {

    private final SessionRepository sessionRepository;

    public SessionService(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    public Session initializeSession() throws UnsupportedEncodingException {

        log.debug("Initializing new session");
        String state = RandomStringUtils.randomAlphanumeric(32);
        String codeVerifier = PkceUtil.generateCodeVerifier();

        return sessionRepository.addSession(state, codeVerifier);
    }

    public void updateSession(String sessionId, Token token) {
        sessionRepository.updateSession(sessionId, token);
    }

    public void clearSession(String sessionId) {
        sessionRepository.clearSession(sessionId);
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
}
