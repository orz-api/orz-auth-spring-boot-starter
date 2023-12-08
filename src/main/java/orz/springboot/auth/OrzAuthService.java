package orz.springboot.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.util.CollectionUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;
import orz.springboot.auth.annotation.OrzAuth;
import orz.springboot.auth.model.OrzAuthConfigBo;
import orz.springboot.auth.model.OrzAuthContextBo;
import orz.springboot.auth.model.OrzAuthTokenBo;
import orz.springboot.auth.model.OrzAuthTokenPayloadBo;
import orz.springboot.base.OrzBaseUtils;
import orz.springboot.web.OrzWebUtils;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

import static orz.springboot.alarm.OrzAlarmUtils.alarm;
import static orz.springboot.base.OrzBaseUtils.hashMap;
import static orz.springboot.base.description.OrzDescriptionUtils.desc;

@Slf4j
public abstract class OrzAuthService implements InitializingBean {
    private static final String TOKEN_PAYLOAD_ATTRIBUTE_NAME = "ORZ_AUTH_TOKEN_PAYLOAD";
    private static final String USER_PAYLOAD_ATTRIBUTE_NAME = "ORZ_AUTH_USER_PAYLOAD";

    public static boolean isCurrentAuthorized() {
        return OrzBaseUtils.getRequestAttribute(TOKEN_PAYLOAD_ATTRIBUTE_NAME).isPresent();
    }

    public static OrzAuthTokenPayloadBo getCurrentTokenPayload() {
        return OrzBaseUtils.<OrzAuthTokenPayloadBo>getRequestAttribute(TOKEN_PAYLOAD_ATTRIBUTE_NAME)
                .orElseThrow(() -> new ResponseStatusException(401, "unauthorized", null));
    }

    protected static <U> U getCurrentUserPayload() {
        if (!isCurrentAuthorized()) {
            throw new ResponseStatusException(401, "unauthorized", null);
        }
        return OrzBaseUtils.<U>getRequestAttribute(USER_PAYLOAD_ATTRIBUTE_NAME)
                .orElse(null);
    }

    @Getter
    private final String scope;

    @Getter(AccessLevel.PROTECTED)
    @Setter(AccessLevel.PROTECTED)
    private OrzAuthProps props;

    @Getter(AccessLevel.PROTECTED)
    @Setter(AccessLevel.PROTECTED)
    private ObjectMapper objectMapper;

    @Getter(AccessLevel.PROTECTED)
    @Setter(AccessLevel.PROTECTED)
    private OrzAuthTokenStore tokenStore;

    protected OrzAuthService() {
        this.scope = obtainScope();
    }

    @Override
    public void afterPropertiesSet() {
        if (props == null) {
            props = OrzBaseUtils.getAppContext().getBean(OrzAuthProps.class);
        }
        if (objectMapper == null) {
            objectMapper = OrzBaseUtils.getAppContext().getBean(ObjectMapper.class);
        }
        if (tokenStore == null) {
            tokenStore = obtainTokenStore();
        }
    }

    public OrzAuthTokenBo createToken(String userId, String clientType) {
        var tokenConfig = props.getTokenConfig(scope);

        var accessTokenExpiresTime = OffsetDateTime.now().plusSeconds(tokenConfig.getAccessTokenValiditySeconds());
        var accessToken = tokenStore.createAccessToken(new OrzAuthTokenPayloadBo(
                UUID.randomUUID().toString(),
                userId,
                clientType,
                accessTokenExpiresTime
        ));

        var refreshTokenExpiresTime = OffsetDateTime.now().plusSeconds(tokenConfig.getRefreshTokenValiditySeconds());
        var refreshToken = tokenStore.createRefreshToken(new OrzAuthTokenPayloadBo(
                UUID.randomUUID().toString(),
                userId,
                clientType,
                refreshTokenExpiresTime
        ));

        return new OrzAuthTokenBo(
                accessToken,
                refreshToken,
                accessTokenExpiresTime,
                refreshTokenExpiresTime
        );
    }

    public OrzAuthTokenBo refreshToken(String token) throws OrzAuthTokenVerifyException {
        var tokenPayload = tokenStore.verifyToken(token);
        return createToken(tokenPayload.getUserId(), tokenPayload.getClientType());
    }

    public void authorize(HttpServletRequest request, HttpServletResponse response, Object handler) {
        var context = new OrzAuthContextBo(request, response, handler);
        context.setConfig(obtainConfig(context));
        context.setTokenPayload(obtainTokenPayload(context));
        if (context.getTokenPayload() != null) {
            checkClientType(context);
            if (context.getConfig().isCheckRequestHeader()) {
                checkRequestHeader(context);
            }
            var userPayload = obtainUserPayload(context);
            if (userPayload != null) {
                OrzBaseUtils.setRequestAttribute(USER_PAYLOAD_ATTRIBUTE_NAME, userPayload);
            }
            OrzBaseUtils.setRequestAttribute(TOKEN_PAYLOAD_ATTRIBUTE_NAME, context.getTokenPayload());
        }
    }

    protected String obtainScope() {
        return OrzWebUtils.getScope(getClass());
    }

    protected OrzAuthTokenStore obtainTokenStore() {
        var jwtConfig = props.getJwtConfig(scope);
        return new OrzAuthTokenStoreJwt(objectMapper, jwtConfig.getJksPath(), jwtConfig.getJksPassword(), jwtConfig.getJksAliasName(), jwtConfig.getJksAliasPassword());
    }

    protected OrzAuthConfigBo obtainConfig(OrzAuthContextBo context) {
        var optional = new boolean[]{false};
        var checkRequestHeader = new boolean[]{true};
        var allowClientTypeSet = new LinkedHashSet<String>();
        if (context.getHandler() instanceof HandlerMethod handlerMethod) {
            var annotation = (OrzAuth) null;
            if (handlerMethod.hasMethodAnnotation(OrzAuth.class)) {
                annotation = handlerMethod.getMethodAnnotation(OrzAuth.class);
            } else if (AnnotatedElementUtils.hasAnnotation(handlerMethod.getBeanType(), OrzAuth.class)) {
                annotation = AnnotationUtils.findAnnotation(handlerMethod.getBeanType(), OrzAuth.class);
            }
            if (annotation != null) {
                optional[0] = annotation.optional();
                checkRequestHeader[0] = annotation.checkRequestHeader();
                allowClientTypeSet.addAll(Arrays.asList(annotation.allowClientTypes()));
            }
        }
        props.getPathConfigs(context.getRequest().getRequestURI()).forEach(path -> {
            if (path.getOptional() != null) {
                optional[0] |= path.getOptional();
            }
            if (path.getCheckRequestHeader() != null) {
                checkRequestHeader[0] &= path.getCheckRequestHeader();
            }
            allowClientTypeSet.addAll(path.getAllowClientTypes());
        });
        return new OrzAuthConfigBo(optional[0], checkRequestHeader[0], allowClientTypeSet);
    }

    protected OrzAuthTokenPayloadBo obtainTokenPayload(OrzAuthContextBo context) {
        var authorization = context.getRequest().getHeader(HttpHeaders.AUTHORIZATION);

        Function<RuntimeException, OrzAuthTokenPayloadBo> nullOrThrow = e -> {
            if (context.getConfig().isOptional()) {
                return null;
            }
            throw e;
        };

        if (StringUtils.isEmpty(authorization)) {
            return nullOrThrow.apply(new ResponseStatusException(401, "header authorization not provided", null));
        }

        if (!StringUtils.startsWithIgnoreCase(authorization, "bearer ")) {
            return nullOrThrow.apply(new ResponseStatusException(401, "header authorization not bearer", null));
        }

        var accessToken = authorization.substring("bearer ".length());
        if (StringUtils.isEmpty(accessToken)) {
            return nullOrThrow.apply(new ResponseStatusException(401, "access token not provided", null));
        }

        try {
            return tokenStore.verifyToken(accessToken);
        } catch (OrzAuthTokenVerifyException e) {
            return nullOrThrow.apply(new ResponseStatusException(401, e.getError().name(), e));
        }
    }

    protected void checkClientType(OrzAuthContextBo context) {
        if (!CollectionUtils.isEmpty(context.getConfig().getAllowClientTypeSet())) {
            if (!context.getConfig().getAllowClientTypeSet().contains(context.getTokenPayload().getClientType())) {
                throw new ResponseStatusException(403, "clientType not allowed", null);
            }
        }
    }

    protected void checkRequestHeader(OrzAuthContextBo context) {
        var payload = context.getTokenPayload();
        var headers = OrzWebUtils.extractRequestHeaders();
        var userIdMismatch = false;
        if (StringUtils.isNotBlank(headers.getUserId())) {
            userIdMismatch = !Objects.equals(headers.getUserId(), payload.getUserId());
        } else {
            userIdMismatch = !context.getConfig().isOptional();
        }
        if (userIdMismatch) {
            log.error(desc("request header mismatch", "field", "userId",
                    "headerUserId", headers.getUserId(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenClientType", payload.getClientType()
            ));
            alarm("@ORZ_AUTH_CHECK_HEADER_FAILED", "userId mismatch", null, hashMap(
                    "headerUserId", headers.getUserId(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenClientType", payload.getClientType()
            ));
        }
        boolean clientTypeMismatch = !Objects.equals(headers.getClientType(), payload.getClientType());
        if (clientTypeMismatch) {
            log.error(desc("request header mismatch", "field", "clientType",
                    "headerUserId", headers.getUserId(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenClientType", payload.getClientType()
            ));
            alarm("@ORZ_AUTH_CHECK_HEADER_FAILED", "clientType mismatch", null, hashMap(
                    "headerUserId", headers.getUserId(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenClientType", payload.getClientType()
            ));
        }
        if (userIdMismatch || clientTypeMismatch) {
            if (!context.getConfig().isOptional()) {
                throw new ResponseStatusException(403, "request header invalid", null);
            }
        }
    }

    @Nullable
    protected Object obtainUserPayload(OrzAuthContextBo context) {
        return null;
    }
}
