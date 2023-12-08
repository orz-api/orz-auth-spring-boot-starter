package orz.springboot.auth.api.scope_v2;

import lombok.Data;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import orz.springboot.auth.annotation.OrzAuth;
import orz.springboot.auth.api.scope_v2.misc.AuthService;
import orz.springboot.web.annotation.OrzWebApi;

import java.time.OffsetDateTime;

@OrzAuth(optional = true)
@OrzWebApi(domain = "Token", action = "Create", variant = 1)
public class TokenCreateV1Api {
    private final AuthService authService;

    public TokenCreateV1Api(AuthService authService) {
        this.authService = authService;
    }

    public TokenCreateV1ApiRsp request(@Validated @RequestBody TokenCreateV1ApiReq req) {
        var token = authService.createToken("1", "test");
        return new TokenCreateV1ApiRsp(
                token.getAccessToken(), token.getRefreshToken(),
                token.getAccessTokenExpiresTime(), token.getRefreshTokenExpiresTime()
        );
    }

    @Data
    public static class TokenCreateV1ApiReq {
    }

    @Data
    public static class TokenCreateV1ApiRsp {
        private final String accessToken;
        private final String refreshToken;
        private final OffsetDateTime accessTokenExpiresTime;
        private final OffsetDateTime refreshTokenExpiresTime;
    }
}
