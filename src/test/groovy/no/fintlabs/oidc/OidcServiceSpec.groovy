package no.fintlabs.oidc

import no.fintlabs.ApplicationConfiguration
import no.fintlabs.controller.Headers
import no.fintlabs.session.InMemorySessionRepository
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
    ApplicationConfiguration configuration
    SessionRepository sessionRepository
    CookieService cookieService
    OidcRequestFactory oidcRequestFactory
    SessionService sessionService
    CodeVerifierCache codeVerifierCache

    void setup() {
        mockWebServer = new MockWebServer()
        mockWebServer.start(8090)

        configuration = new ApplicationConfiguration()
        configuration.setIssuerUri(mockWebServer.url("/").toString())
        sessionRepository = new InMemorySessionRepository(configuration)
        cookieService = new CookieService(configuration)
        oidcRequestFactory = new OidcRequestFactory(configuration)
        sessionService = new SessionService(sessionRepository)
        codeVerifierCache = new CodeVerifierCache()
        oidcService = new OidcService(configuration, WebClient.create(), oidcRequestFactory, codeVerifierCache)

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


    def "Should successfully fetch token"() {
        given:
        def headers = new HttpHeaders()
        headers.set(Headers.X_FORWARDED_HOST, "localhost")
        headers.set(Headers.X_FORWARDED_PORT, "80")
        headers.set(Headers.X_FORWARDED_PROTO, "http")

        oidcService.fetchWellKnowConfiguration()
        def authUrl = oidcService.getAuthorizationUri(headers).toString()
        def queryParameters = UriComponentsBuilder.fromUriString(authUrl.toString())
                .build()
                .getQueryParams()
        def state = queryParameters.getFirst("state")
        codeVerifierCache.storeCodeVerifier(state, "")

        when:
        def token = oidcService.fetchToken(Maps.of("state", state, "code", "code"), headers).block()

        then:
        assert token != null
    }

    def "Should fail due to wrong state being sent"() {
        given:
        def headers = new HttpHeaders()
        headers.set(Headers.X_FORWARDED_HOST, "localhost")
        headers.set(Headers.X_FORWARDED_PORT, "80")
        headers.set(Headers.X_FORWARDED_PROTO, "http")

        oidcService.fetchWellKnowConfiguration()
        def authUrl = oidcService.getAuthorizationUri(headers).toString()
        def queryParameters = UriComponentsBuilder.fromUriString(authUrl.toString())
                .build()
                .getQueryParams()
        def state = queryParameters.getFirst("state")
        codeVerifierCache.storeCodeVerifier(state, "")

        when:
        def result = oidcService.fetchToken(Maps.of("state", "wrongState", "code", "code"), headers).block()

        then:
        def exception = thrown(InvalidState)
        exception.message == "Invalid state"
    }
}
