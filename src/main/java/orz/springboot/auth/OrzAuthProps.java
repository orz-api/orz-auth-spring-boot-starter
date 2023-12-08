package orz.springboot.auth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.AntPathMatcher;
import org.springframework.validation.annotation.Validated;
import orz.springboot.alarm.exception.OrzUnexpectedException;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Data
@Validated
@ConfigurationProperties(prefix = "orz.auth")
public class OrzAuthProps {
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    @Valid
    @NotNull
    private TokenConfig token = new TokenConfig();

    @Valid
    private JwtConfig jwt = null;

    @Valid
    @NotNull
    private Map<String, ScopeConfig> scopes = Collections.emptyMap();

    @Valid
    @NotNull
    private Map<String, PathConfig> paths = Collections.emptyMap();

    public TokenConfig getTokenConfig(String scope) {
        var tokenConfig = Optional.ofNullable(scopes.get(scope)).map(ScopeConfig::getToken).orElseGet(() -> token);
        if (tokenConfig == null) {
            throw new OrzUnexpectedException("OrzAuthProps token config not set", "scope", scope);
        }
        return tokenConfig;
    }

    public JwtConfig getJwtConfig(String scope) {
        var jwtConfig = Optional.ofNullable(scopes.get(scope)).map(ScopeConfig::getJwt).orElseGet(() -> jwt);
        if (jwtConfig == null) {
            throw new OrzUnexpectedException("OrzAuthProps jwt config not set", "scope", scope);
        }
        return jwtConfig;
    }

    public List<PathConfig> getPathConfigs(String path) {
        return paths.entrySet().stream()
                .filter(e -> PATH_MATCHER.match(e.getKey(), path))
                .map(Map.Entry::getValue)
                .collect(Collectors.toList());
    }

    @Data
    public static class TokenConfig {
        @Positive
        private int accessTokenValiditySeconds = 604800;

        @Positive
        private int refreshTokenValiditySeconds = 2592000;
    }

    @Data
    public static class JwtConfig {
        @NotBlank
        private String jksPath;

        @NotBlank
        private String jksPassword;

        @NotBlank
        private String jksAliasName;

        @NotBlank
        private String jksAliasPassword;
    }

    @Data
    public static class ScopeConfig {
        @Valid
        private TokenConfig token = null;

        @Valid
        private JwtConfig jwt = null;
    }

    @Data
    public static class PathConfig {
        private Boolean optional = null;

        private Boolean checkRequestHeader = null;

        @NotNull
        private List<String> allowClientTypes = Collections.emptyList();
    }
}
