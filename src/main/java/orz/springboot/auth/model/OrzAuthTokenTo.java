package orz.springboot.auth.model;

import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OrzAuthTokenTo {
    private String userId;
    private String userRole;
    private String accessToken;
    private String refreshToken;
    private OffsetDateTime accessTokenExpiresTime;
    private OffsetDateTime refreshTokenExpiresTime;
    @Nullable
    private Map<String, Object> extras;

    public static OrzAuthTokenTo of(OrzAuthTokenBo bo) {
        return new OrzAuthTokenTo(
                bo.getUserId(),
                bo.getUserRole(),
                bo.getAccessToken(),
                bo.getRefreshToken(),
                bo.getAccessTokenExpiresTime(),
                bo.getRefreshTokenExpiresTime(),
                bo.getExtras()
        );
    }
}
