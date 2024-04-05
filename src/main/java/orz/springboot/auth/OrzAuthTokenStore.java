package orz.springboot.auth;

import orz.springboot.auth.model.OrzAuthTokenPayloadBo;
import orz.springboot.auth.model.OrzAuthTokenTypeBo;

public interface OrzAuthTokenStore {
    String createToken(OrzAuthTokenPayloadBo payload);

    OrzAuthTokenPayloadBo verifyToken(String token, OrzAuthTokenTypeBo type) throws OrzAuthTokenVerifyException;
}
