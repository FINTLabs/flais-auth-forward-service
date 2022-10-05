package no.fintlabs;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
public class AuthController {

    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

    public AuthController(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping()
    public Mono<ResponseEntity<Void>> auth() {
        log.info("");

        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication().getName())
                .flatMap(this::getAccessToken)
                .map(token -> ResponseEntity.ok().header(HttpHeaders.AUTHORIZATION, "Bearer " + token).build());
    }

    private Mono<String> getAccessToken(String name) {
        return authorizedClientService
                .loadAuthorizedClient("fint", name)
                .map(client -> client.getAccessToken().getTokenValue());
    }


}
