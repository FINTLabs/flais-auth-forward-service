package no.fintlabs.controller;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.ApplicationConfiguration;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Slf4j
@Controller
public class UiController {

    private final ApplicationConfiguration applicationConfiguration;

    public UiController(ApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    @GetMapping("_oauth/logged-out")
    public String loggedOut(Model model) {
        model.addAttribute("title", "Logged out");
        model.addAttribute("message", applicationConfiguration.getLogoutMessage());
        return "logged-out";
    }

    @GetMapping("_oauth/error")
    public String error(@RequestParam(value = "reason", required = false) String reason, Model model) {
        model.addAttribute("title", "Error");
        if (reason != null && !reason.isEmpty()) {
            model.addAttribute("reason", reason);
        }
        return "error";
    }
}
