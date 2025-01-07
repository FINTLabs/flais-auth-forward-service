package no.fintlabs.oidc

import no.fintlabs.ApplicationConfiguration
import no.fintlabs.controller.Headers
import no.fintlabs.session.ConcurrentHashMapSessionRepository
import no.fintlabs.session.CookieService
import no.fintlabs.session.SessionRepository
import no.fintlabs.session.SessionService
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.apache.groovy.util.Maps
import org.jetbrains.annotations.NotNull
import org.springframework.core.io.ClassPathResource
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.mock.http.server.reactive.MockServerHttpResponse
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.util.UriComponentsBuilder
import spock.lang.Specification

class OidcServiceSpec extends Specification {

    MockWebServer mockWebServer
    OidcService oidcService
    ApplicationConfiguration configuration
    SessionRepository sessionRepository
    CookieService cookieService
    OidcRequestFactory oidcRequestFactory
    SessionService sessionService

    void setup() {
        mockWebServer = new MockWebServer()
        mockWebServer.start(8090)

        configuration = new ApplicationConfiguration()
        configuration.setIssuerUri(mockWebServer.url("/").toString())
        sessionRepository = new ConcurrentHashMapSessionRepository(configuration)
        cookieService = new CookieService(configuration)
        oidcRequestFactory = new OidcRequestFactory(configuration)
        sessionService = new SessionService(configuration, sessionRepository)
        oidcService = new OidcService(configuration, WebClient.create(), oidcRequestFactory)

        def dispatcher = new Dispatcher() {
            @Override
            MockResponse dispatch(@NotNull RecordedRequest request) throws InterruptedException {
                switch (request.getPath()) {
                    case "/" + OidcService.WELL_KNOWN_OPENID_CONFIGURATION_PATH:
                        return new MockResponse()
                                .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                                .setBody(new ClassPathResource('well-known.json').getFile().text)

                    case "/keys":
                        return new MockResponse()
                                .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                                .setBody(new ClassPathResource('jwk.json').getFile().text)

                    case "/token?resourceServer=fint-api":
                        return new MockResponse()
                                .setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                                .setBody(new ClassPathResource('token.json').getFile().text)

                }
                return new MockResponse().setResponseCode(404)
            }
        }

        mockWebServer.setDispatcher(dispatcher)


    }

    void cleanup() {
        mockWebServer.shutdown()
    }

    def "When fetching well know configuration the property should be set in the service"() {

        when:
        oidcService.fetchWellKnowConfiguration()

        then:
        oidcService.getWellKnownConfiguration()
    }

    def "When fetching JWK the property should be set in the service"() {
        given:
        oidcService.fetchWellKnowConfiguration()

        when:
        oidcService.fetchJwks()

        then:
        oidcService.getJwk()
    }


    def "Successfully fetching token should set the token in the session repository"() {
        given:
        def headers = new HttpHeaders()
        headers.set(Headers.X_FORWARDED_HOST, "localhost")
        headers.set(Headers.X_FORWARDED_PORT, "80")
        headers.set(Headers.X_FORWARDED_PROTO, "http")

        oidcService.fetchWellKnowConfiguration()
        def session = sessionService.initializeSession()
        def queryParameters = UriComponentsBuilder.fromHttpUrl(oidcService.getAuthorizationUri(headers, session).toString()).build().getQueryParams()


        when:
        oidcService.fetchToken(Maps.of("state", queryParameters.getFirst("state"), "code", "code"), headers).block()

        then:
        sessionRepository.getSessions().size() == 1
        sessionRepository.getTokenBySessionId(queryParameters.getFirst("state")).isPresent()
    }

    def "Logout should remove session"() {

        given:
        def session = sessionService.initializeSession()
        def sessionCount = sessionService.sessionCount()

        when:
        oidcService.logout(new MockServerHttpResponse(), Optional.of("signature." + session.getSessionId()))

        then:
        (sessionCount - 1) == sessionService.sessionCount()
    }
}
