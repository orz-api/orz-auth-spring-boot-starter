package orz.springboot.auth.model;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;

@Data
public class OrzAuthContextBo {
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final Object handler;

    private OrzAuthConfigBo config;
    private OrzAuthTokenPayloadBo tokenPayload;
}
