package no.fintlabs.oidc

import no.fintlabs.ApplicationConfiguration
import no.fintlabs.session.Session
import org.springframework.http.HttpHeaders
import org.springframework.web.util.UriComponentsBuilder
import spock.lang.Specification

class OidcRequestFactorySpec extends Specification {

    OidcRequestFactory oidcRequestFactory


    void setup() {
        def configuration = new ApplicationConfiguration()
        oidcRequestFactory = new OidcRequestFactory(configuration)
    }

    def "Fetch token  request body should have 6 elements and grant_type should be authorization_code"() {
        when:
        def body = OidcRequestFactory
                .createTokenRequestBody("clientId", "clientSecret", "code", "callbackUri", "codeVerifier")

        then:
        body.size() == 6
        body.get("grant_type").get(0) == "authorization_code"
    }

    def "Authorization URI should have response_type to be code"() {
        when:
        def uri = oidcRequestFactory.createAuthorizationUri("http://localhost", new HttpHeaders(), "state", "codeVerifier")
        def uriComponents = UriComponentsBuilder.fromUri(uri).build()
        then:
        uriComponents.getQueryParams().size() == 9
        uriComponents.getQueryParams().getFirst("response_type") == "code"
    }

    def "Authorization URI should have valid PKCE"() {
        when:
        def codeVerifier = "1234"
        def uri = oidcRequestFactory.createAuthorizationUri("http://localhost", new HttpHeaders(), "state", codeVerifier)
        def uriComponents = UriComponentsBuilder.fromUri(uri).build()
        def codeChallenge = PkceUtil.generateCodeChallenge(codeVerifier)
        then:
        assert uriComponents.getQueryParams().size() == 9
        assert uriComponents.getQueryParams().getFirst("code_challenge_method") == PkceUtil.codeChallengeMethod
        assert uriComponents.getQueryParams().getFirst("code_challenge") == codeChallenge
    }

    def "If enforce https is enabled port should be null"() {

        when:
        def port = oidcRequestFactory.getPort(new HttpHeaders())

        then:
        port == null

    }

    def "If enforce https is enabled protocol should be https"() {

        when:
        def protocol = oidcRequestFactory.getProtocol(new HttpHeaders())

        then:
        protocol == "https"

    }
}
