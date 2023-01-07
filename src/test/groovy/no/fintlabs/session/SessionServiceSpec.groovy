package no.fintlabs.session

import no.fintlabs.ApplicationConfiguration
import spock.lang.Specification

import java.time.LocalDateTime

class SessionServiceSpec extends Specification {

    def "Old sessions should be removed"() {
        given:
        def repository = new ConcurrentHashMapSessionRepository()
        def configuration = new ApplicationConfiguration()
        def sessionService = new SessionService(configuration, repository)

        sessionService.initializeSession()
        sessionService.initializeSession()
        sessionService.initializeSession()
        sessionService.initializeSession(LocalDateTime.now().minusMinutes(1440))

        when:
        def beforeCleanup = sessionService.sessionCount()
        sessionService.cleanupOldSessions()
        def afterCleanup = sessionService.sessionCount()

        then:
        afterCleanup == beforeCleanup - 1
    }
}
