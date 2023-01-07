package no.fintlabs

import com.fasterxml.jackson.databind.ObjectMapper
import no.fintlabs.oidc.OidcService
import no.fintlabs.oidc.Token
import no.fintlabs.oidc.UnableToVerifyTokenSignature
import no.fintlabs.session.ConcurrentHashMapSessionRepository
import no.fintlabs.session.CookieService
import no.fintlabs.session.Session
import no.fintlabs.session.SessionService
import org.spockframework.spring.SpringBean
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest
import org.springframework.core.io.ClassPathResource
import org.springframework.http.HttpHeaders
import org.springframework.test.web.reactive.server.WebTestClient
import spock.lang.Specification

@WebFluxTest(controllers = AuthController.class)
class AuthControllerSpec extends Specification {

    WebTestClient webTestClient

    @SpringBean
    ApplicationConfiguration configuration = new ApplicationConfiguration()

    @SpringBean
    CookieService cookieService = new CookieService(configuration)

    @SpringBean
    SessionService sessionService = new SessionService(configuration, new ConcurrentHashMapSessionRepository())

    @SpringBean
    OidcService oidcService = Mock(OidcService.class)

    void setup() {
        def controller = new AuthController(oidcService, cookieService, sessionService)

        webTestClient = WebTestClient.bindToController(controller).build()

        configuration.setVerifyTokenSignature(false)
    }

    def "If no valid authentication is present we should return 307 and a new session should be initialized"() {
        given:
        def sessionCount = sessionService.sessionCount()
        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .exchange()


        then:
        oidcService.getAuthorizationUri(_ as HttpHeaders, _ as Session) >> URI.create("authorizationUri")
        response.expectStatus()
                .isTemporaryRedirect()
        response.expectHeader()
                .location("authorizationUri")
        sessionCount + 1 == sessionService.sessionCount()

    }

    def "If cookie, session and token is verified everything should be ok"() {

        given:
        def session = sessionService.initializeSession()
        def cookie = cookieService.createAuthenticationCookie(session.getState(), 3600)
        sessionService.updateSession(session.getState(),
                new ObjectMapper().readValue(new ClassPathResource('token.json').getFile(), Token.class))

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
        def session = sessionService.initializeSession()
        def cookie = cookieService.createAuthenticationCookie(session.getState(), 3600)
        sessionService.updateSession(session.getState(),
                new ObjectMapper().readValue(new ClassPathResource('token.json').getFile(), Token.class))

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
        def session = sessionService.initializeSession()
        def cookie = cookieService.createAuthenticationCookie(session.getState(), 3600)
        sessionService.updateSession(session.getState(),
                new ObjectMapper().readValue(new ClassPathResource('token.json').getFile(), Token.class))

        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookieService.createAuthenticationCookie("fake-state", 360).getValue())
                .exchange()

        then:
        response.expectStatus().isTemporaryRedirect()
    }

    def "If token is not verified we should get 403"() {

        given:
        def session = sessionService.initializeSession()
        def cookie = cookieService.createAuthenticationCookie(session.getState(), 3600)
        sessionService.updateSession(session.getState(),
                new ObjectMapper().readValue(new ClassPathResource('token.json').getFile(), Token.class))

        when:
        def response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange()

        then:
        oidcService.verifyToken(_ as Token) >> { throw new UnableToVerifyTokenSignature() }
        response.expectStatus().isForbidden()
    }
}
