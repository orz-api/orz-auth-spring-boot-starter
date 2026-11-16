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
public class OrzAuthTokenInfoTo {
    private String userId;
    private String userType;
    private String accessToken;
    private String refreshToken;
    private OffsetDateTime accessTokenExpiresTime;
    private OffsetDateTime refreshTokenExpiresTime;
    private String issuer;
    @Nullable
    private Map<String, Object> extras;

    public static OrzAuthTokenInfoTo of(OrzAuthTokenInfoBo bo) {
        return new OrzAuthTokenInfoTo(
                bo.getUserId(),
                bo.getUserType(),
                bo.getAccessToken(),
                bo.getRefreshToken(),
                bo.getAccessTokenExpiresTime(),
                bo.getRefreshTokenExpiresTime(),
                bo.getIssuer(),
                bo.getExtras()
        );
    }
}
