package orz.springboot.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.ResourceUtils;
import orz.springboot.auth.model.OrzAuthTokenPayloadBo;
import orz.springboot.auth.model.OrzAuthTokenPayloadPo;
import orz.springboot.auth.model.OrzAuthTokenTypeBo;
import orz.springboot.auth.model.OrzAuthTokenTypePo;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Objects;

import static orz.springboot.auth.OrzAuthTokenVerifyError.TOKEN_EXPIRED;
import static orz.springboot.auth.OrzAuthTokenVerifyError.TOKEN_INVALID;
import static orz.springboot.base.description.OrzDescriptionUtils.descValues;

public class OrzAuthJwtTokenStore implements OrzAuthTokenStore {
    private static final TypeReference<LinkedHashMap<String, Object>> PAYLOAD_TYPE = new TypeReference<>() {
    };

    private final JsonMapper jsonMapper;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;

    public OrzAuthJwtTokenStore(JsonMapper jsonMapper, String jksPath, String jksPassword, String jksAliasName, String jksAliasPassword) {
        this.jsonMapper = jsonMapper;
        this.algorithm = loadJksAlgorithm(jksPath, jksPassword, jksAliasName, jksAliasPassword);
        this.verifier = JWT.require(algorithm).build();
    }

    @Override
    public String createToken(OrzAuthTokenPayloadBo payload) {
        var payloadMap = jsonMapper.convertValue(
                new OrzAuthTokenPayloadPo(
                        payload.getUuid(),
                        payload.getUserId(),
                        payload.getUserType(),
                        payload.getClientType(),
                        payload.getExpiresTime(),
                        payload.getCreateTime(),
                        OrzAuthTokenTypePo.valueOf(payload.getTokenType().name()),
                        payload.getIssuer(),
                        payload.getExtras()
                ),
                PAYLOAD_TYPE
        );
        return JWT.create()
                .withPayload(payloadMap)
                .sign(algorithm);
    }

    @Override
    public OrzAuthTokenPayloadBo verifyToken(String token, OrzAuthTokenTypeBo type) throws OrzAuthTokenVerifyException {
        var payload = (OrzAuthTokenPayloadPo) null;
        try {
            var payloadBase64 = verifier.verify(token).getPayload();
            payload = jsonMapper.readValue(Base64.getDecoder().decode(payloadBase64), OrzAuthTokenPayloadPo.class);
        } catch (TokenExpiredException e) {
            throw new OrzAuthTokenVerifyException(TOKEN_EXPIRED, e);
        } catch (Exception e) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, e);
        }
        if (StringUtils.isBlank(payload.getUuid())) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "uuid"));
        }
        if (StringUtils.isBlank(payload.getUserId())) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "userId"));
        }
        if (StringUtils.isBlank(payload.getUserType())) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "userType"));
        }
        if (StringUtils.isBlank(payload.getClientType())) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "clientType"));
        }
        if (StringUtils.isBlank(payload.getIssuer())) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "issuer"));
        }

        if (payload.getTokenType() == null) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "tokenType"));
        }
        if (!Objects.equals(payload.getTokenType().name(), type.name())) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "tokenType", "expected", type, "actual", payload.getTokenType()));
        }

        if (payload.getCreateTime() == null) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "createTime"));
        }
        if (payload.getExpiresTime() == null) {
            throw new OrzAuthTokenVerifyException(TOKEN_INVALID, descValues("field", "expiresTime"));
        }
        var now = OffsetDateTime.now();
        if (payload.getExpiresTime().isBefore(now)) {
            throw new OrzAuthTokenVerifyException(TOKEN_EXPIRED, (Throwable) null);
        }

        return new OrzAuthTokenPayloadBo(
                payload.getUuid(),
                payload.getUserId(),
                payload.getUserType(),
                payload.getClientType(),
                payload.getExpiresTime(),
                payload.getCreateTime(),
                type,
                payload.getIssuer(),
                payload.getExtras()
        );
    }

    @SneakyThrows
    private static Algorithm loadJksAlgorithm(String jksPath, String jksPassword, String jksAliasName, String jksAliasPassword) {
        var keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ResourceUtils.getURL(jksPath).openStream(), jksPassword.toCharArray());
        var publicKey = (RSAPublicKey) keyStore.getCertificate(jksAliasName).getPublicKey();
        var privateKey = (RSAPrivateKey) keyStore.getKey(jksAliasName, jksAliasPassword.toCharArray());
        return Algorithm.RSA256(publicKey, privateKey);
    }
}
