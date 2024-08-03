package orz.springboot.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AppTests {
    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestRestTemplate testRestTemplate;

    @SneakyThrows
    @Test
    void testScopeV1TestAccessV1Api() {
        var url = "/ScopeV1/Test/QueryV1";
        var req = new orz.springboot.auth.api.scope_v1.TestQueryV1Api.TestQueryV1ApiReq();
        var rspClass = orz.springboot.auth.api.scope_v1.TestQueryV1Api.TestQueryV1ApiRsp.class;

        // Not provide token
        {
            queryMockMvc(url, req, null)
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            var response = queryTestRestTemplate(url, req, rspClass, null);
            assertEquals(401, response.getStatusCode().value());
            assertFalse(response.getHeaders().containsKey("Orz-Version"));
        }

        // Provide error token
        {
            queryMockMvc(url, req, "error")
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            var response = queryTestRestTemplate(url, req, rspClass, "error");
            assertEquals(401, response.getStatusCode().value());
            assertFalse(response.getHeaders().containsKey("Orz-Version"));
        }

        // Provide other scope token
        {
            var tokenReq = new orz.springboot.auth.api.scope_v2.TokenCreateV1Api.TokenCreateV1ApiReq();
            var tokenRspClass = orz.springboot.auth.api.scope_v2.TokenCreateV1Api.TokenCreateV1ApiRsp.class;
            var token = testRestTemplate.postForObject("/ScopeV2/Token/CreateV1", tokenReq, tokenRspClass).getAccessToken();
            assertNotNull(token);

            queryMockMvc(url, req, token)
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            var response = queryTestRestTemplate(url, req, rspClass, token);
            assertEquals(401, response.getStatusCode().value());
            assertFalse(response.getHeaders().containsKey("Orz-Version"));
        }

        // Provide correct token
        {
            var tokenReq = new orz.springboot.auth.api.scope_v1.TokenCreateV1Api.TokenCreateV1ApiReq();
            var tokenRspClass = orz.springboot.auth.api.scope_v1.TokenCreateV1Api.TokenCreateV1ApiRsp.class;
            var token = testRestTemplate.postForObject("/ScopeV1/Token/CreateV1", tokenReq, tokenRspClass).getAccessToken();
            assertNotNull(token);

            queryMockMvc(url, req, token)
                    .andExpect(status().isOk())
                    .andExpect(MockMvcResultMatchers.header().exists("Orz-Version"));

            var response = queryTestRestTemplate(url, req, rspClass, token);
            assertEquals(200, response.getStatusCode().value());
            assertTrue(response.getHeaders().containsKey("Orz-Version"));
            assertNotNull(response.getBody());
            assertEquals("1", response.getBody().getUserId());
            assertEquals("test", response.getBody().getClientType());
            assertEquals("1234", response.getBody().getUserName());
        }
    }

    @SneakyThrows
    @Test
    void testScopeV2TestAccessV1Api() {
        var url = "/ScopeV2/Test/QueryV1";
        var req = new orz.springboot.auth.api.scope_v2.TestQueryV1Api.TestQueryV1ApiReq();
        var rspClass = orz.springboot.auth.api.scope_v2.TestQueryV1Api.TestQueryV1ApiRsp.class;

        // Not provide token
        {
            queryMockMvc(url, req, null)
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            var response = queryTestRestTemplate(url, req, rspClass, null);
            assertEquals(401, response.getStatusCode().value());
            assertFalse(response.getHeaders().containsKey("Orz-Version"));
        }

        // Provide error token
        {
            queryMockMvc(url, req, "error")
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            var response = queryTestRestTemplate(url, req, rspClass, "error");
            assertEquals(401, response.getStatusCode().value());
            assertFalse(response.getHeaders().containsKey("Orz-Version"));
        }

        // Provide other scope token
        {
            var tokenReq = new orz.springboot.auth.api.scope_v1.TokenCreateV1Api.TokenCreateV1ApiReq();
            var tokenRspClass = orz.springboot.auth.api.scope_v1.TokenCreateV1Api.TokenCreateV1ApiRsp.class;
            var token = testRestTemplate.postForObject("/ScopeV1/Token/CreateV1", tokenReq, tokenRspClass).getAccessToken();
            assertNotNull(token);

            queryMockMvc(url, req, token)
                    .andExpect(status().isUnauthorized())
                    .andExpect(MockMvcResultMatchers.header().doesNotExist("Orz-Version"));

            var response = queryTestRestTemplate(url, req, rspClass, token);
            assertEquals(401, response.getStatusCode().value());
            assertFalse(response.getHeaders().containsKey("Orz-Version"));
        }

        // Provide correct token
        {
            var tokenReq = new orz.springboot.auth.api.scope_v2.TokenCreateV1Api.TokenCreateV1ApiReq();
            var tokenRspClass = orz.springboot.auth.api.scope_v2.TokenCreateV1Api.TokenCreateV1ApiRsp.class;
            var token = testRestTemplate.postForObject("/ScopeV2/Token/CreateV1", tokenReq, tokenRspClass).getAccessToken();
            assertNotNull(token);

            queryMockMvc(url, req, token)
                    .andExpect(status().isOk())
                    .andExpect(MockMvcResultMatchers.header().exists("Orz-Version"));

            var response = queryTestRestTemplate(url, req, rspClass, token);
            assertEquals(200, response.getStatusCode().value());
            assertTrue(response.getHeaders().containsKey("Orz-Version"));
            assertNotNull(response.getBody());
            assertEquals("1", response.getBody().getUserId());
            assertEquals("test", response.getBody().getClientType());
        }
    }

    @SneakyThrows
    private ResultActions queryMockMvc(String url, Object req, String token) {
        var builder = put(url)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req));
        if (token != null) {
            builder = builder.header("Authorization", "Bearer " + token);
        }
        return mockMvc.perform(builder);
    }

    @SneakyThrows
    private ResultActions mutationMockMvc(String url, Object req, String token) {
        var builder = post(url)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req));
        if (token != null) {
            builder = builder.header("Authorization", "Bearer " + token);
        }
        return mockMvc.perform(builder);
    }

    @SneakyThrows
    private <T> ResponseEntity<T> queryTestRestTemplate(String url, Object req, Class<T> rspClass, String token) {
        var restTemplate = testRestTemplate.getRestTemplate();
        var responseExtractor = restTemplate.<T>responseEntityExtractor(rspClass);
        if (token == null) {
            var requestCallback = restTemplate.httpEntityCallback(req, rspClass);
            return restTemplate.execute(url, HttpMethod.PUT, requestCallback, responseExtractor);
        } else {
            var headers = new HttpHeaders();
            headers.setBearerAuth(token);
            var entity = new HttpEntity<>(req, headers);
            var requestCallback = restTemplate.httpEntityCallback(entity, rspClass);
            return restTemplate.execute(url, HttpMethod.PUT, requestCallback, responseExtractor);
        }
    }

    @SneakyThrows
    private <T> ResponseEntity<T> mutationTestRestTemplate(String url, Object req, Class<T> rspClass, String token) {
        if (token == null) {
            return testRestTemplate.postForEntity(url, req, rspClass);
        } else {
            var headers = new HttpHeaders();
            headers.setBearerAuth(token);
            var entity = new HttpEntity<>(req, headers);
            return testRestTemplate.postForEntity(url, entity, rspClass);
        }
    }
}
