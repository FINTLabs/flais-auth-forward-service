package no.fintlabs.session;

import no.fintlabs.MissingAuthentication;
import no.fintlabs.oidc.PkceUtil;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;

@Service
public class SessionService {

    private final SessionRepository sessionRepository;

    public SessionService(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    public Session initializeSession() throws UnsupportedEncodingException {
        String state = RandomStringUtils.randomAlphanumeric(32);
        String codeVerifier = PkceUtil.generateCodeVerifier();

        return sessionRepository.addSession(state, codeVerifier);
    }

    public Session verifySession(String sessionId) throws MissingAuthentication {
        return sessionRepository.getTokenBySessionId(CookieService.getStateFromValue(sessionId))
                .orElseThrow(MissingAuthentication::new);
    }
}
