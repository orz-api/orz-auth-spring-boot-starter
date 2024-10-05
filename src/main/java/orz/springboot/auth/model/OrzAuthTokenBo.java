package orz.springboot.auth.model;

import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class OrzAuthTokenBo {
    private final String userId;
    private final String accessToken;
    private final String refreshToken;
    private final OffsetDateTime accessTokenExpiresTime;
    private final OffsetDateTime refreshTokenExpiresTime;
    private final String userRole;
}
