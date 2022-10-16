package no.fintlabs.oidc

import no.fintlabs.Headers
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
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.util.UriComponentsBuilder
import spock.lang.Specification

class OidcServiceSpec extends Specification {

    MockWebServer mockWebServer
    OidcService oidcService
    OidcConfiguration oidcConfiguration
    SessionRepository sessionRepository
    CookieService cookieService
    OidcRequestFactory oidcRequestFactory
    SessionService sessionService

    void setup() {
        mockWebServer = new MockWebServer()
        mockWebServer.start(8090)

        oidcConfiguration = new OidcConfiguration()
        oidcConfiguration.setIssuerUri(UriComponentsBuilder.fromUri(URI.create(mockWebServer.url("/").toString())))
        sessionRepository = new ConcurrentHashMapSessionRepository()
        cookieService = new CookieService(oidcConfiguration)
        oidcRequestFactory = new OidcRequestFactory(oidcConfiguration)
        oidcService = new OidcService(oidcConfiguration, WebClient.create(), sessionRepository, cookieService, oidcRequestFactory)
        sessionService = new SessionService(sessionRepository)

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
                return new MockResponse().setResponseCode(404);
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
        def queryParameters = UriComponentsBuilder.fromHttpUrl(oidcService.createAuthorizationUri(headers, session).toString()).build().getQueryParams()


        when:
        oidcService.fetchToken(Maps.of("state", queryParameters.getFirst("state"), "code", "code"), headers).block()

        then:
        sessionRepository.getSessions().size() == 1
        sessionRepository.getTokenBySessionId(queryParameters.getFirst("state")).isPresent()
    }
}
