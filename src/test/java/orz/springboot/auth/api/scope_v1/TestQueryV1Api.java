package orz.springboot.auth.api.scope_v1;

import lombok.Data;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestBody;
import orz.springboot.auth.api.scope_v1.misc.AuthService;
import orz.springboot.web.annotation.OrzWebApi;

@OrzWebApi(domain = "Test", action = "Query", variant = 1, query = true)
public class TestQueryV1Api {
    public TestQueryV1ApiRsp request(@Validated @RequestBody TestQueryV1ApiReq req) {
        var userId = AuthService.getUserId();
        var clientType = AuthService.getClientType();
        var userName = AuthService.getUserName();
        return new TestQueryV1ApiRsp(userId, clientType, userName);
    }

    @Data
    public static class TestQueryV1ApiReq {
    }

    @Data
    public static class TestQueryV1ApiRsp {
        private final String userId;
        private final String clientType;
        private final String userName;
    }
}
