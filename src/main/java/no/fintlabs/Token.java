package no.fintlabs;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class Token {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expires_in")
    private long expiresIn;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("scope")
    private String scope;

    /*
    {"access_token":
"eyJhbGciOiJSU0ExXzU......",
"token_type": "bearer","expires_in": 179,
"refresh_token": "eyJhbGcidHlwIjoiSldUIiwiemlwjo..........",
"scope": "email"}
     */
}
