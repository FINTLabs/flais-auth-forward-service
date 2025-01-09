package no.fintlabs

import com.auth0.jwt.JWT
import com.fasterxml.jackson.databind.ObjectMapper
import no.fintlabs.controller.AuthController
import no.fintlabs.oidc.*
import no.fintlabs.session.InMemorySessionRepository
import no.fintlabs.session.CookieService
import no.fintlabs.session.SessionRepository
import no.fintlabs.session.SessionService
import org.spockframework.spring.SpringBean
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest
import org.springframework.core.io.ClassPathResource
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import spock.lang.Specification

import java.time.Instant

@WebFluxTest(controllers = AuthController.class)
class AuthControllerSpec extends Specification {

    WebTestClient webTestClient

    WebClient oidcWebClient = Mock(WebClient)

    @SpringBean
    ApplicationConfiguration configuration = new ApplicationConfiguration()

    @SpringBean
    CookieService cookieService = new CookieService(configuration)

    SessionRepository sessionRepository =  new InMemorySessionRepository(configuration)

    @SpringBean
    SessionService sessionService = new SessionService(sessionRepository)


    CodeVerifierCache codeVerifierCache = new CodeVerifierCache();

    @SpringBean
    OidcService oidcService = new OidcService(
            configuration,
            oidcWebClient,
            new OidcRequestFactory(configuration),
            codeVerifierCache
    )

    void setup() {
        def controller = new AuthController(oidcService, cookieService, sessionService)

        webTestClient = WebTestClient.bindToController(controller).build()

        configuration.setVerifyTokenSignature(false)

        oidcService.setWellKnownConfiguration(new WellKnownConfiguration(authorizationEndpoint: "authorizationEndpoint"))
        oidcService.setJwk(new ObjectMapper().readValue(new ClassPathResource('jwk.json').getFile(), Jwk.class))
    }

    def "If no valid authentication is present we should return 307 and state and code verifier should be generated"() {
        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .exchange()

        then:
        response.expectStatus()
                .isTemporaryRedirect()
        def locationHeader = response.returnResult(Void.class).responseHeaders.getFirst(HttpHeaders.LOCATION)
        assert locationHeader != null

        def uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build()
        def queryParams = uriComponents.getQueryParams()
        def state = queryParams.getFirst("state")

        assert state != null
        def codeVerifier = codeVerifierCache.getCodeVerifier(state)
        assert codeVerifier != null
    }

    def "If cookie, session and token is verified everything should be ok"() {

        given:
        def session = sessionService.initializeSession(TokenFactory.createTokenWithoutSignature())
        def cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600)

        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange()

        then:
        notThrown(UnableToVerifyTokenSignature.class)
        response.expectStatus().isOk().expectHeader().exists(HttpHeaders.AUTHORIZATION)
    }

    def "If cookie is not valid we should be redirected for authentication"() {

        given:
        def session = sessionService.initializeSession(
                TokenFactory.createTokenWithoutSignature())
        def cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600)

        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), "hash-secret.fake-cookie-value")
                .exchange()

        then:
        response.expectStatus().isTemporaryRedirect()
    }

    def "If cookie is valid but session is not valid we should be redirected for authentication"() {

        given:
        def session = sessionService.initializeSession(TokenFactory.createTokenWithoutSignature())
        def cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600)

        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookieService.createAuthenticationCookie("fake-state", 360).getValue())
                .exchange()

        then:
        response.expectStatus().isTemporaryRedirect()
    }

    def "Should refetch token when session is about to expire"() {
        given:
        def origToken = TokenFactory.createTokenWithoutSignature(Instant.now().plusSeconds(10))
        def session = sessionService.initializeSession(origToken)
        def cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600)

        def requestBodyUriSpec = Mock(WebClient.RequestBodyUriSpec)
        def requestBodySpec = Mock(WebClient.RequestBodySpec)
        def requestHeadersSpec = Mock(WebClient.RequestHeadersSpec)
        def responseSpec = Mock(WebClient.ResponseSpec)

        def newToken = TokenFactory.createTokenWithoutSignature(Instant.now().plusSeconds(3600))
        def capturedToken

        oidcWebClient.post() >> requestBodyUriSpec
        requestBodyUriSpec.uri(_ as String) >> requestBodySpec
        requestBodySpec.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE) >> requestBodySpec
        requestBodySpec.body(_ as BodyInserters.FormInserter) >> { args ->
            capturedToken = (args[0] as BodyInserters.FormInserter)["data"]["refresh_token"][0] as String
            return requestHeadersSpec
        }
        requestHeadersSpec.retrieve() >> responseSpec
        responseSpec.bodyToMono(Token) >> Mono.just(newToken)

        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange()

        then:
        response.expectStatus().isOk()
        assert capturedToken != null
        assert capturedToken == origToken.refreshToken
        response.expectHeader().valueEquals("Authorization", "Bearer " + newToken.accessToken)

        def updatedSession = sessionService.getSession(session.sessionId).block()
        assert updatedSession.token == newToken
        def accessToken =  JWT.decode(updatedSession.token.accessToken)
        assert updatedSession.tokenExpiresAt == sessionRepository.dateToLocalDateTime(accessToken.expiresAt)
    }

    def "If token is not verified we should get 403"() {

        given:
        def session = sessionService.initializeSession(TokenFactory.createTokenWithSignature())
        def cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600)


        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange()

        then:
        response.expectStatus().isForbidden()
    }

    def "When logging out the session should be removed"() {
        given:
        def session = sessionService.initializeSession(TokenFactory.createTokenWithoutSignature())
        def cookie = cookieService.createAuthenticationCookie(session.getSessionId(), configuration.getSessionMaxAgeInMinutes())

        def sessionCountBeforeLogout = sessionService.sessionCount()

        when:
        webTestClient
                .get()
                .uri("/_oauth/logout")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange()
        def sessionCountAfterLogout = sessionService.sessionCount()

        then:
        sessionCountAfterLogout == sessionCountBeforeLogout - 1
    }
}
