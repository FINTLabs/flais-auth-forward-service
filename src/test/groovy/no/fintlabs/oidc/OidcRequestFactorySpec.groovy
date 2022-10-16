package no.fintlabs.oidc


import spock.lang.Specification

class OidcRequestFactorySpec extends Specification {

    def "Fetch token  request body should have 5 elements and grant_type should be authorization_code"() {
        when:
        def body = OidcRequestFactory
                .createTokenRequestBody("clientId", "clientSecret", "code", "callbackUri")

        then:
        body.size() == 5
        body.get("grant_type").get(0) == "authorization_code"
    }
}
