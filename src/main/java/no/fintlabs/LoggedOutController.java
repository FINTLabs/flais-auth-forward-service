package no.fintlabs;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.oidc.OidcConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.result.view.Rendering;
import reactor.core.publisher.Mono;

@Slf4j
@Controller
public class LoggedOutController {

    private final OidcConfiguration oidcConfiguration;

    public LoggedOutController(OidcConfiguration oidcConfiguration) {
        this.oidcConfiguration = oidcConfiguration;
    }

    @GetMapping(value = "logged-out")
    public Mono<Rendering> loggedOut() {

        return Mono.just(Rendering.view("index").modelAttribute("message", oidcConfiguration.getLogoutMessage()).build());
    }
}
