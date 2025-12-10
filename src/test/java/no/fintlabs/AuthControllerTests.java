package no.fintlabs;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import no.fintlabs.oidc.*;
import no.fintlabs.session.CookieService;
import no.fintlabs.session.InMemorySessionRepository;
import no.fintlabs.session.SessionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.lang.reflect.Field;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SpringBootTest
@AutoConfigureWebTestClient
class AuthControllerTests {
    @Autowired
    WebTestClient webTestClient;

    @Autowired
    SessionService sessionService;

    @Autowired
    CookieService cookieService;

    @Autowired
    CodeVerifierCache codeVerifierCache;

    @MockitoSpyBean
    WebClient oidcWebClient;

    @TestBean
    ApplicationConfiguration configuration;

    @Autowired
    private InMemorySessionRepository inMemorySessionRepository;

    static ApplicationConfiguration configuration() {
        var config = new ApplicationConfiguration();
        config.setVerifyTokenSignature(false);
        return config;
    }

    @BeforeAll
    static void setup(@Autowired OidcService oidcService) throws IOException {
        var wellKnownConfiguration =  new WellKnownConfiguration();
        wellKnownConfiguration.setAuthorizationEndpoint("authorizationEndpoint");
        oidcService.setWellKnownConfiguration(wellKnownConfiguration);
        oidcService.setJwk(new ObjectMapper().readValue(new ClassPathResource("jwk.json").getFile(), Jwk.class));
    }

    @Test
    void If_no_valid_authentication_is_present_we_should_return_307_and_state_and_code_verifier_should_be_generated() {
        var response = webTestClient
                .get()
                .uri("/_oauth")
                .exchange();

        response.expectStatus()
                .isTemporaryRedirect();

        var locationHeader = response.returnResult(Void.class).getResponseHeaders().getFirst(HttpHeaders.LOCATION);
        assertNotNull(locationHeader);

        var uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
        var queryParams = uriComponents.getQueryParams();

        var state = queryParams.getFirst("state");
        assertNotNull(state);
        assertNotNull(queryParams.getFirst("code_challenge"));
        assertEquals("S256", queryParams.getFirst("code_challenge_method"));

        var codeVerifier = codeVerifierCache.getCodeVerifier(state);
        assertNotNull(codeVerifier);
    }

    @Test
    void If_cookie_session_and_token_is_verified_everything_should_be_ok() {
        var session = sessionService.initializeSession(TokenFactory.createTokenWithoutSignature());
        var cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600);

        var response = assertDoesNotThrow(() -> webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange());

        response.expectStatus().isOk().expectHeader().exists(HttpHeaders.AUTHORIZATION);
    }

    @Test
    void If_cookie_is_not_valid_we_should_be_redirected_for_authentication() {
        var session = sessionService.initializeSession(TokenFactory.createTokenWithoutSignature());
        var cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600);

        var response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), "hash-secret.fake-cookie-value")
                .exchange();

        response.expectStatus().isTemporaryRedirect();
        response.expectHeader().valueMatches(HttpHeaders.LOCATION, "authorizationEndpoint.*");
    }

    @Test
    void If_cookie_is_valid_but_session_is_not_valid_we_should_be_redirected_for_authentication() {
        var session = sessionService.initializeSession(TokenFactory.createTokenWithoutSignature());
        var cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600);

        var response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookieService.createAuthenticationCookie("fake-state", 360).getValue())
                .exchange();

        response.expectStatus().isTemporaryRedirect();
        response.expectHeader().valueMatches(HttpHeaders.LOCATION, "authorizationEndpoint.*");
    }

    @Test
    void Should_refetch_token_when_session_is_about_to_expire() throws NoSuchFieldException, IllegalAccessException {
        var origToken = TokenFactory.createTokenWithoutSignature(Instant.now().plusSeconds(10));
        var session = sessionService.initializeSession(origToken);
        var cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600);

        var requestBodyUriSpec = mock(WebClient.RequestBodyUriSpec.class);
        var requestBodySpec = mock(WebClient.RequestBodySpec.class);
        var requestHeadersSpec = mock(WebClient.RequestHeadersSpec.class);
        var responseSpec = mock(WebClient.ResponseSpec.class);

        var newToken = TokenFactory.createTokenWithoutSignature(Instant.now().plusSeconds(3600));

        when(oidcWebClient.post()).thenAnswer(a ->
                requestBodyUriSpec);
        when(requestBodyUriSpec.uri(any(String.class))).thenAnswer(a ->
                requestBodySpec);
        when(requestBodySpec.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE))
                .thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(BodyInserters.FormInserter.class))).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(any(Class.class))).thenReturn(Mono.just(newToken));

        var response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange();


        var argCapturer = ArgumentCaptor.forClass(BodyInserters.FormInserter.class);
        verify(requestBodySpec).body(argCapturer.capture());

        BodyInserters.FormInserter<?> inserter = argCapturer.getValue();
        Field dataField = inserter.getClass().getDeclaredField("data");
        dataField.setAccessible(true);

        @SuppressWarnings("unchecked")
        MultiValueMap<String, String> form = (MultiValueMap<String, String>) dataField.get(inserter);
        var token = form.get("refresh_token").get(0);


        response.expectStatus().isOk();
        assertNotNull(token);
        assertEquals(token, origToken.getRefreshToken());
        response.expectHeader().valueEquals("Authorization", "Bearer " + newToken.getAccessToken());

        var updatedSession = sessionService.getSession(session.getSessionId()).block();
        assertNotNull(updatedSession);
        assertEquals(updatedSession.getToken(), newToken);
        var accessToken =  JWT.decode(updatedSession.getToken().getAccessToken());
        assertEquals(updatedSession.getTokenExpiresAt(), inMemorySessionRepository.dateToLocalDateTime(accessToken.getExpiresAt()));
    }

    @Test
    void If_token_is_not_verified_we_should_get_redirect_to_error_page() {
        var session = sessionService.initializeSession(TokenFactory.createTokenWithSignature());
        var cookie = cookieService.createAuthenticationCookie(session.getSessionId(), 3600);


        var response = webTestClient
                .get()
                .uri("/_oauth")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange();

        response.expectStatus().is3xxRedirection();
        response.expectHeader().valueMatches(HttpHeaders.LOCATION, "/_oauth/error.*");
    }

    @Test
    void When_logging_out_the_session_should_be_removed() {
        var session = sessionService.initializeSession(TokenFactory.createTokenWithoutSignature());
        var cookie = cookieService.createAuthenticationCookie(session.getSessionId(), configuration.getSessionMaxAgeInMinutes());

        var sessionCountBeforeLogout = sessionService.sessionCount();

        webTestClient
                .get()
                .uri("/_oauth/logout")
                .cookie(cookie.getName(), cookie.getValue())
                .exchange();
        var sessionCountAfterLogout = sessionService.sessionCount();

        assertEquals(sessionCountAfterLogout, sessionCountBeforeLogout - 1);
    }
}
