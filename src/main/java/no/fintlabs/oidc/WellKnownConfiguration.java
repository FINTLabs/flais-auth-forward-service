package no.fintlabs.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class WellKnownConfiguration {

    @JsonProperty("issuer")
    private String issuer;

    @JsonProperty("authorization_endpoint")
    private String authorizationEndpoint;

    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    @JsonProperty("userinfo_endpoint")
    private String userinfoEndpoint;

    @JsonProperty("revocation_endpoint")
    private String revocationEndpoint;

    @JsonProperty("introspection_endpoint")
    private String introspectionEndpoint;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("registration_endpoint")
    private String registrationEndpoint;

    @JsonProperty("scopes_supported")
    private List<String> scopesSupported = new ArrayList<>();

    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported = new ArrayList<>();

    @JsonProperty("response_modes_supported")
    private List<String> responseModesSupported = new ArrayList<>();

    @JsonProperty("grant_types_supported")
    private List<String> grantTypesSupported = new ArrayList<>();

    @JsonProperty("id_token_signing_alg_values_supported")
    private List<String> idTokenSigningAlgValuesSupported = new ArrayList<>();

    @JsonProperty("claims_supported")
    private List<String> claimsSupported = new ArrayList<>();

    @JsonProperty("token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported = new ArrayList<>();

    @JsonProperty("revocation_endpoint_auth_methods_supported")
    private List<String> revocationEndpointAuthMethodsSupported = new ArrayList<>();

    @JsonProperty("introspection_endpoint_auth_methods_supported")
    private List<String> introspectionEndpointAuthMethodsSupported = new ArrayList<>();

    @JsonProperty("subject_types_supported")
    private List<String> subjectTypesSupported = new ArrayList<>();

    @JsonProperty("code_challenge_methods_supported")
    private List<String> codeChallengeMethodsSupported = new ArrayList<>();
}
