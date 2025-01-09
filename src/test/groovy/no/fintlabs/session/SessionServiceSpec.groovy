package no.fintlabs.session

import no.fintlabs.ApplicationConfiguration
import no.fintlabs.TokenFactory
import spock.lang.Specification

import java.time.Instant
import java.time.ZoneId
import java.time.temporal.ChronoUnit

class SessionServiceSpec extends Specification {

    SessionRepository repository
    ApplicationConfiguration configuration
    SessionService sessionService

    void setup() {
        configuration = new ApplicationConfiguration()
        repository = new InMemorySessionRepository(configuration)
        sessionService = new SessionService(repository)
    }

    def "Should create new session"() {
        given:
        def expectedSession = sessionService.initializeSession(TokenFactory.createTokenWithSignature())

        when:
        def session = sessionService.getSession(expectedSession.getSessionId()).block()

        then:
        assert session != null
        assert expectedSession.sessionId == session.sessionId
    }

    def "Should extract correct token values"() {
        given:
        def expire = Instant.now()

        when:
        def session = sessionService.initializeSession(TokenFactory.createTokenWithoutSignature(expire))

        then:
        assert session != null
        assert session.tokenExpiresAt == expire.atZone(ZoneId.systemDefault()).toLocalDateTime().truncatedTo(ChronoUnit.SECONDS)
    }
}
