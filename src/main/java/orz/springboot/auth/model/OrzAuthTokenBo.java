package orz.springboot.auth.model;

import jakarta.annotation.Nullable;
import lombok.Data;

import java.time.OffsetDateTime;
import java.util.Map;

@Data
public class OrzAuthTokenBo {
    private final String userId;
    private final String userType;
    private final String accessToken;
    private final String refreshToken;
    private final OffsetDateTime accessTokenExpiresTime;
    private final OffsetDateTime refreshTokenExpiresTime;
    @Nullable
    private final Map<String, Object> extras;
}
