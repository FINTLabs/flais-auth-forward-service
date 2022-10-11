package no.fintlabs.oidc;

import com.auth0.jwk.InvalidPublicKeyException;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Data;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


@Data
@JsonPropertyOrder({
        "kty",
        "use",
        "alg",
        "kid",
        "x5c",
        "x5t",
        "x5tS256",
        "n",
        "e"
})
public class Key {

    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_ELLIPTIC_CURVE = "EC";
    private static final String ELLIPTIC_CURVE_TYPE_P256 = "P-256";
    private static final String ELLIPTIC_CURVE_TYPE_P384 = "P-384";
    private static final String ELLIPTIC_CURVE_TYPE_P521 = "P-521";
    @JsonProperty("kty")
    private String keyType;
    @JsonProperty("use")
    private String use;
    @JsonProperty("alg")
    private String algorithm;
    @JsonProperty("kid")
    private String keyId;
    @JsonProperty("x5c")
    private List<String> x5c = new ArrayList<>();
    @JsonProperty("x5t")
    private String x5t;
    @JsonProperty("x5tS256")
    private String x5tS256;
    @JsonProperty("n")
    private String n;
    @JsonProperty("e")
    private String e;

    public PublicKey getPublicKey() throws InvalidPublicKeyException {
        PublicKey publicKey;


        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM_RSA);
            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
            BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
            publicKey = kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (InvalidKeySpecException e) {
            throw new InvalidPublicKeyException("Invalid public key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidPublicKeyException("Invalid algorithm to generate key", e);
        }


        return publicKey;
    }

}