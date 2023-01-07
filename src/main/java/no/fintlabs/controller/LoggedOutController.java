package no.fintlabs.controller;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.result.view.Rendering;
import reactor.core.publisher.Mono;

@Slf4j
@Controller
public class LoggedOutController {

    private final ApplicationConfiguration applicationConfiguration;

    public LoggedOutController(ApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    @GetMapping(value = "_oauth/logged-out")
    public Mono<Rendering> loggedOut() {

        return Mono.just(Rendering.view("index").modelAttribute("message", applicationConfiguration.getLogoutMessage()).build());
    }
}
