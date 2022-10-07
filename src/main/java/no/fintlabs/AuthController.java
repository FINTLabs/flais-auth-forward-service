package no.fintlabs;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@RestController
public class AuthController {

private final WebClient webClient;

    public AuthController(WebClient webClient) {
        this.webClient = webClient;
    }

    @GetMapping("auth")
    public Mono<ResponseEntity<String>> auth(@RequestHeader Map<String, String> headers, ServerHttpResponse response, ServerHttpRequest request) {
        log.info("Request headers:");
        headers.forEach((s, s2) -> log.info("\t{}: {}", s, s2));


//        Cookie cookie = new Cookie();
//        cookie.setDomain("frode");
//        cookie.setHttpOnly(true);
//        cookie.setPath("/");
//        ResponseCookie build = ResponseCookie.from("test", UUID.randomUUID().toString())
//                //.domain(r)
//                .httpOnly(true)
//                .secure(request.getURI().getScheme().equalsIgnoreCase("https"))
//                .path("/")
//                .build();
//        response.addCookie(build);
//
//        return Mono.just(ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, build.toString()).build());

    }


}
