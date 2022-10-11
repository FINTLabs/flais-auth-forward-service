package no.fintlabs.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


@Data
public class Jwk {

    @JsonProperty("keys")
    private List<Key> keys = new ArrayList<>();

    public Optional<Key> getKeyById(String id) {
        return keys.stream().filter(key -> key.getKeyId().equals(id)).findAny();
    }
}