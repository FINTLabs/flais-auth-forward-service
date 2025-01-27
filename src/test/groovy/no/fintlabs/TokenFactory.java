package no.fintlabs;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import net.bytebuddy.utility.RandomString;
import no.fintlabs.oidc.Token;
import org.apache.commons.lang3.RandomStringUtils;

import java.time.Instant;

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
