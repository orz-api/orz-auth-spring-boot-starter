package orz.springboot.auth;

import orz.springboot.auth.model.OrzAuthTokenPayloadBo;

public interface OrzAuthTokenStore {
    String createAccessToken(OrzAuthTokenPayloadBo payload);

    String createRefreshToken(OrzAuthTokenPayloadBo payload);

    OrzAuthTokenPayloadBo verifyToken(String token) throws OrzAuthTokenVerifyException;
}
