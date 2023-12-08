package orz.springboot.auth.api.scope_v2.misc;

import org.springframework.stereotype.Service;
import orz.springboot.auth.OrzAuthService;

@Service
public class AuthService extends OrzAuthService {
    public static String getUserId() {
        return getCurrentTokenPayload().getUserId();
    }

    public static String getClientType() {
        return getCurrentTokenPayload().getClientType();
    }
}
