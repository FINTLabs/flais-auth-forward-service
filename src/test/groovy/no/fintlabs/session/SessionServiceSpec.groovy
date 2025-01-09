package no.fintlabs.session

import no.fintlabs.ApplicationConfiguration
import no.fintlabs.TokenFactory
import spock.lang.Specification

import java.time.LocalDateTime

class SessionServiceSpec extends Specification {

    SessionRepository repository
    ApplicationConfiguration configuration
    SessionService sessionService

    void setup() {
        configuration = new ApplicationConfiguration()
        repository = new InMemorySessionRepository(configuration)
        sessionService = new SessionService(configuration, repository)
    }

    def "If session was initialized more than max session age in minutes ago it should be considered not active"() {
        given:
        def session = sessionService.initializeSession(LocalDateTime.now().minusMinutes(configuration.getSessionMaxAgeInMinutes() + 1))
        sessionService.updateSession(session.getSessionId(), TokenFactory.createTokenWithSignature())

        when:
        def active = sessionService.isSessionActive(session)

        then:
        !active
    }

    def "If session was initialized less than max session age in minutes ago it should be considered active"() {
        given:
        def session = sessionService.initializeSession(LocalDateTime.now().minusMinutes(configuration.getSessionMaxAgeInMinutes() - 10))
        sessionService.updateSession(session.getSessionId(), TokenFactory.createTokenWithSignature())

        when:
        def active = sessionService.isSessionActive(session)

        then:
        active
    }

//    def "If session don't contain a token is should be considered not active"() {
//        given:
//        def session = sessionService.initializeSession()
//
//        when:
//        def active = sessionService.isSessionActive(session)
//
//        then:
//        !active
//    }

    def "Get active session should only return active sessions"() {
        given:
        sessionService.initializeSession()
        sessionService.initializeSession()
        def activeSession = sessionService.initializeSession()
        sessionService.updateSession(activeSession.getSessionId(), TokenFactory.createTokenWithSignature())

        when:
        def sessionCount = sessionService.sessionCount()
        def activeSessionCount = sessionService.getActiveSessions().size()

        then:
        sessionCount == 3
        activeSessionCount == 1
    }
}
