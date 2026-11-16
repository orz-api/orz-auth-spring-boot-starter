package orz.springboot.auth;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureRestTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.client.RestTestClient;
import org.springframework.test.web.servlet.client.RestTestClient.ResponseSpec;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import tools.jackson.databind.json.JsonMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@AutoConfigureRestTestClient
class AppTests {
    @Autowired
    private JsonMapper jsonMapper;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RestTestClient restTestClient;

    @SneakyThrows
    @Test
    void testScopeV1TestAccessV1Api() {
        var uri = "/ScopeV1/Test/QueryV1";
        var req = new orz.springboot.auth.api.scope_v1.TestQueryV1Api.TestQueryV1ApiReq();
        var rspClass = orz.springboot.auth.api.scope_v1.TestQueryV1Api.TestQueryV1ApiRsp.class;

        // Not provide token
        {
            queryMockMvc(uri, req, null)
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            queryRestTestClient(uri, req, null)
                    .expectStatus().isEqualTo(401)
                    .expectHeader().doesNotExist("Orz-Version");
        }

        // Provide error token
        {
            queryMockMvc(uri, req, "error")
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            queryRestTestClient(uri, req, "error")
                    .expectStatus().isEqualTo(401)
                    .expectHeader().doesNotExist("Orz-Version");
        }

        // Provide other scope token
        {
            var tokenReq = new orz.springboot.auth.api.scope_v2.TokenCreateV1Api.TokenCreateV1ApiReq();
            var tokenRspClass = orz.springboot.auth.api.scope_v2.TokenCreateV1Api.TokenCreateV1ApiRsp.class;
            var tokenRsp = mutationRestTestClient("/ScopeV2/Token/CreateV1", tokenReq, null)
                    .expectStatus().isEqualTo(200)
                    .expectHeader().exists("Orz-Version")
                    .expectBody(tokenRspClass).returnResult().getResponseBody();
            assertNotNull(tokenRsp);
            assertNotNull(tokenRsp.getAccessToken());
            assertNotNull(tokenRsp.getAccessTokenExpiresTime());
            assertNotNull(tokenRsp.getRefreshToken());
            assertNotNull(tokenRsp.getRefreshTokenExpiresTime());

            queryMockMvc(uri, req, tokenRsp.getAccessToken())
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            queryRestTestClient(uri, req, tokenRsp.getAccessToken())
                    .expectStatus().isEqualTo(401)
                    .expectHeader().doesNotExist("Orz-Version");
        }

        // Provide correct token
        {
            var tokenReq = new orz.springboot.auth.api.scope_v1.TokenCreateV1Api.TokenCreateV1ApiReq();
            var tokenRspClass = orz.springboot.auth.api.scope_v1.TokenCreateV1Api.TokenCreateV1ApiRsp.class;
            var tokenRsp = mutationRestTestClient("/ScopeV1/Token/CreateV1", tokenReq, null)
                    .expectStatus().isEqualTo(200)
                    .expectHeader().exists("Orz-Version")
                    .expectBody(tokenRspClass).returnResult().getResponseBody();
            assertNotNull(tokenRsp);
            assertNotNull(tokenRsp.getAccessToken());
            assertNotNull(tokenRsp.getAccessTokenExpiresTime());
            assertNotNull(tokenRsp.getRefreshToken());
            assertNotNull(tokenRsp.getRefreshTokenExpiresTime());

            queryMockMvc(uri, req, tokenRsp.getAccessToken())
                    .andExpect(status().isOk())
                    .andExpect(MockMvcResultMatchers.header().exists("Orz-Version"))
                    .andExpect(MockMvcResultMatchers.content().json("{\"userId\":\"1\",\"clientType\":\"test\",\"userName\":\"1234\"}"));

            queryRestTestClient(uri, req, tokenRsp.getAccessToken())
                    .expectStatus().isEqualTo(200)
                    .expectHeader().exists("Orz-Version")
                    .expectBody(rspClass).consumeWith(result -> {
                        assertNotNull(result.getResponseBody());
                        assertEquals("1", result.getResponseBody().getUserId());
                        assertEquals("test", result.getResponseBody().getClientType());
                        assertEquals("1234", result.getResponseBody().getUserName());
                    });
        }
    }

    @SneakyThrows
    @Test
    void testScopeV2TestAccessV1Api() {
        var uri = "/ScopeV2/Test/QueryV1";
        var req = new orz.springboot.auth.api.scope_v2.TestQueryV1Api.TestQueryV1ApiReq();
        var rspClass = orz.springboot.auth.api.scope_v2.TestQueryV1Api.TestQueryV1ApiRsp.class;

        // Not provide token
        {
            queryMockMvc(uri, req, null)
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            queryRestTestClient(uri, req, null)
                    .expectStatus().isEqualTo(401)
                    .expectHeader().doesNotExist("Orz-Version");
        }

        // Provide error token
        {
            queryMockMvc(uri, req, "error")
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            queryRestTestClient(uri, req, "error")
                    .expectStatus().isEqualTo(401)
                    .expectHeader().doesNotExist("Orz-Version");
        }

        // Provide other scope token
        {
            var tokenReq = new orz.springboot.auth.api.scope_v1.TokenCreateV1Api.TokenCreateV1ApiReq();
            var tokenRspClass = orz.springboot.auth.api.scope_v1.TokenCreateV1Api.TokenCreateV1ApiRsp.class;
            var tokenRsp = mutationRestTestClient("/ScopeV1/Token/CreateV1", tokenReq, null)
                    .expectStatus().isEqualTo(200)
                    .expectHeader().exists("Orz-Version")
                    .expectBody(tokenRspClass).returnResult().getResponseBody();
            assertNotNull(tokenRsp);
            assertNotNull(tokenRsp.getAccessToken());
            assertNotNull(tokenRsp.getAccessTokenExpiresTime());
            assertNotNull(tokenRsp.getRefreshToken());
            assertNotNull(tokenRsp.getRefreshTokenExpiresTime());

            queryMockMvc(uri, req, tokenRsp.getAccessToken())
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            queryRestTestClient(uri, req, tokenRsp.getAccessToken())
                    .expectStatus().isEqualTo(401)
                    .expectHeader().doesNotExist("Orz-Version");
        }

        // Provide correct token
        {
            var tokenReq = new orz.springboot.auth.api.scope_v2.TokenCreateV1Api.TokenCreateV1ApiReq();
            var tokenRspClass = orz.springboot.auth.api.scope_v2.TokenCreateV1Api.TokenCreateV1ApiRsp.class;
            var tokenRsp = mutationRestTestClient("/ScopeV2/Token/CreateV1", tokenReq, null)
                    .expectStatus().isEqualTo(200)
                    .expectHeader().exists("Orz-Version")
                    .expectBody(tokenRspClass).returnResult().getResponseBody();
            assertNotNull(tokenRsp);
            assertNotNull(tokenRsp.getAccessToken());
            assertNotNull(tokenRsp.getAccessTokenExpiresTime());
            assertNotNull(tokenRsp.getRefreshToken());
            assertNotNull(tokenRsp.getRefreshTokenExpiresTime());

            queryMockMvc(uri, req, tokenRsp.getAccessToken())
                    .andExpect(status().isOk())
                    .andExpect(MockMvcResultMatchers.header().exists("Orz-Version"))
                    .andExpect(MockMvcResultMatchers.content().json("{\"userId\":\"1\",\"clientType\":\"test\"}"));

            queryRestTestClient(uri, req, tokenRsp.getAccessToken())
                    .expectStatus().isEqualTo(200)
                    .expectHeader().exists("Orz-Version")
                    .expectBody(rspClass).consumeWith(result -> {
                        assertNotNull(result.getResponseBody());
                        assertEquals("1", result.getResponseBody().getUserId());
                        assertEquals("test", result.getResponseBody().getClientType());
                    });
        }
    }

    @SneakyThrows
    private ResultActions queryMockMvc(String uri, Object req, String token) {
        var builder = put(uri)
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonMapper.writeValueAsString(req));
        if (token != null) {
            builder = builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return mockMvc.perform(builder);
    }

    @SneakyThrows
    private ResultActions mutationMockMvc(String uri, Object req, String token) {
        var builder = post(uri)
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonMapper.writeValueAsString(req));
        if (token != null) {
            builder = builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return mockMvc.perform(builder);
    }

    @SneakyThrows
    private ResponseSpec queryRestTestClient(String uri, Object req, String token) {
        var spec = restTestClient.put().uri(uri);
        if (token != null) {
            spec = spec.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return spec.body(req).exchange();
    }

    @SneakyThrows
    private ResponseSpec mutationRestTestClient(String uri, Object req, String token) {
        var spec = restTestClient.post().uri(uri);
        if (token != null) {
            spec = spec.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return spec.body(req).exchange();
    }
}
