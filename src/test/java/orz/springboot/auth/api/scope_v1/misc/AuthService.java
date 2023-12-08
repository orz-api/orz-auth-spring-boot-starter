package orz.springboot.auth.api.scope_v1.misc;

import jakarta.annotation.Nullable;
import org.springframework.stereotype.Service;
import orz.springboot.auth.OrzAuthService;
import orz.springboot.auth.model.OrzAuthContextBo;

import java.util.Map;

@Service
public class AuthService extends OrzAuthService {
    public static String getUserId() {
        return getCurrentTokenPayload().getUserId();
    }

    public static String getClientType() {
        return getCurrentTokenPayload().getClientType();
    }

    public static String getUserName() {
        return OrzAuthService.<Map<String, String>>getCurrentUserPayload().get("name");
    }

    @Nullable
    @Override
    protected Object obtainUserPayload(OrzAuthContextBo context) {
        return Map.of("name", "1234");
    }
}
