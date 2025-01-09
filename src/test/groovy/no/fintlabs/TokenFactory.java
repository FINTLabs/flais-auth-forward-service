package no.fintlabs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import no.fintlabs.oidc.Token;
import org.assertj.core.internal.bytebuddy.utility.RandomString;

import java.time.Instant;
import java.util.Date;
import java.util.random.RandomGenerator;

public class TokenFactory {

    public static Token createTokenWithoutSignature() {
        return createTokenWithoutSignature(Instant.now().plusSeconds(3600));
    }

    public static Token createTokenWithoutSignature(Instant expiresAt) {
        return Token.builder()
                .accessToken(JWT
                        .create()
                        .withClaim("email", "ola@norman.no")
                        .withExpiresAt(expiresAt)
                        .sign(Algorithm.none()))
                .refreshToken(RandomString.make(16))
                .tokenType("Bearer")
                .expiresIn(3600)
                .scope("scope")
                .build();

    }

    public static Token createTokenWithSignature() {
        return Token.builder()
                .accessToken(JWT
                        .create()
                        .withClaim("email", "ola@norman.no")
                        .withExpiresAt(Instant.now().plusSeconds(3600))
                        .sign(Algorithm.HMAC256("secret")))
                .refreshToken("refresh_token")
                .tokenType("Bearer")
                .expiresIn(3600)
                .scope("scope")
                .build();

    }
}
