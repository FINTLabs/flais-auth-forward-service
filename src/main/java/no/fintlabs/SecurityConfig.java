package no.fintlabs;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
        return http.authorizeExchange()
                .pathMatchers("/**")
                .permitAll()
                .anyExchange().authenticated()
                .and().oauth2Login(Customizer.withDefaults())
                .build();
    }

    @Bean
    public WebSessionIdResolver webSessionIdResolver() {
        CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
        //resolver.setCookieName("JSESSIONID");

        //resolver.addCookieInitializer((builder) -> builder.httpOnly(true));
        //resolver.addCookieInitializer((builder) -> builder.sameSite("Strict"));
        //resolver.addCookieInitializer((builder) -> builder.secure(true));
        return resolver;
    }
}