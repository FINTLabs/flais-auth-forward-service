package no.fintlabs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import no.fintlabs.oidc.Token;

import java.time.Instant;

public class TokenFactory {

    public static Token createTokenWithoutSignature() {
        return Token.builder()
                .accessToken(JWT
                        .create()
                        .withClaim("email", "ola@norman.no")
                        .withExpiresAt(Instant.now())
                        .sign(Algorithm.none()))
                .refreshToken("refresh_token")
                .tokenType("token_type")
                .expiresIn(3600)
                .scope("scope")
                .build();

    }

    public static Token createTokenWithSignature() {
        return Token.builder()
                .accessToken(JWT
                        .create()
                        .withClaim("email", "ola@norman.no")
                        .withExpiresAt(Instant.now())
                        .sign(Algorithm.HMAC256("secret")))
                .refreshToken("refresh_token")
                .tokenType("token_type")
                .expiresIn(3600)
                .scope("scope")
                .build();

    }
}
