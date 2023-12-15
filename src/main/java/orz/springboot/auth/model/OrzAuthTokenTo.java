package orz.springboot.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OrzAuthTokenTo {
    private String userId;
    private String accessToken;
    private String refreshToken;
    private OffsetDateTime accessTokenExpiresTime;
    private OffsetDateTime refreshTokenExpiresTime;

    public static OrzAuthTokenTo of(OrzAuthTokenBo bo) {
        return new OrzAuthTokenTo(
                bo.getUserId(),
                bo.getAccessToken(),
                bo.getRefreshToken(),
                bo.getAccessTokenExpiresTime(),
                bo.getRefreshTokenExpiresTime()
        );
    }
}
