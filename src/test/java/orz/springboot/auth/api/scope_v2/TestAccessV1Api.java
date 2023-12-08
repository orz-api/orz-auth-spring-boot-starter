package orz.springboot.auth.api.scope_v2;

import lombok.Data;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import orz.springboot.auth.api.scope_v2.misc.AuthService;
import orz.springboot.web.annotation.OrzWebApi;

@OrzWebApi(domain = "Test", action = "Access", variant = 1)
public class TestAccessV1Api {
    public TestAccessV1ApiRsp request(@Validated @RequestBody TestAccessV1ApiReq req) {
        var userId = AuthService.getUserId();
        var clientType = AuthService.getClientType();
        return new TestAccessV1ApiRsp(userId, clientType);
    }

    @Data
    public static class TestAccessV1ApiReq {
    }

    @Data
    public static class TestAccessV1ApiRsp {
        private final String userId;
        private final String clientType;
    }
}
