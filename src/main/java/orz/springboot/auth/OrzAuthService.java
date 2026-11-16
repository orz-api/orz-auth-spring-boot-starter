package orz.springboot.auth;

import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.util.CollectionUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;
import orz.springboot.alarm.exception.OrzUnexpectedException;
import orz.springboot.auth.annotation.OrzAuth;
import orz.springboot.auth.model.*;
import orz.springboot.base.OrzBaseUtils;
import orz.springboot.web.OrzWebUtils;
import tools.jackson.databind.json.JsonMapper;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.function.Function;

import static orz.springboot.alarm.OrzAlarmUtils.alarm;
import static orz.springboot.base.OrzBaseUtils.hashMap;
import static orz.springboot.base.description.OrzDescriptionUtils.desc;

@Slf4j
public abstract class OrzAuthService implements InitializingBean {
    private static final String TOKEN_PAYLOAD_ATTRIBUTE_NAME = "ORZ_AUTH_TOKEN_PAYLOAD";
    private static final String USER_PAYLOAD_ATTRIBUTE_NAME = "ORZ_AUTH_USER_PAYLOAD";

    public static boolean isCurrentAuthorized() {
        return OrzWebUtils.getRequestAttribute(TOKEN_PAYLOAD_ATTRIBUTE_NAME).isPresent();
    }

    public static OrzAuthTokenPayloadBo getCurrentTokenPayload() {
        return OrzWebUtils.<OrzAuthTokenPayloadBo>getRequestAttribute(TOKEN_PAYLOAD_ATTRIBUTE_NAME)
                .orElseThrow(() -> new ResponseStatusException(401, "unauthorized", null));
    }

    protected static <U> U getCurrentUserPayload() {
        if (!isCurrentAuthorized()) {
            throw new ResponseStatusException(401, "unauthorized", null);
        }
        return OrzWebUtils.<U>getRequestAttribute(USER_PAYLOAD_ATTRIBUTE_NAME)
                .orElse(null);
    }

    @Getter
    private final String scope;

    @Getter(AccessLevel.PROTECTED)
    private OrzAuthProps props;

    private String defaultTokenIssuer;
    private OrzAuthTokenStore tokenStore;

    protected OrzAuthService() {
        this.scope = obtainScope();
    }

    @Override
    public void afterPropertiesSet() {
        if (props == null) {
            props = OrzBaseUtils.getAppContext().getBean(OrzAuthProps.class);
        }
        defaultTokenIssuer = props.getTokenConfig(scope).getIssuer();
        OrzBaseUtils.getAppContext().getBean(OrzAuthManager.class).registerService(this);
    }

    public OrzAuthTokenInfoBo createToken(String userId, String userType, String clientType, @Nullable Map<String, Object> extras) {
        return createToken(userId, userType, clientType, extras, null);
    }

    public OrzAuthTokenInfoBo createToken(String userId, String userType, String clientType, @Nullable Map<String, Object> extras, @Nullable String issuer) {
        issuer = defaultIssuer(issuer);
        var tokenConfig = props.getTokenConfig(scope);
        var tokenStore = selectTokenStore(issuer);

        var uuid = UUID.randomUUID().toString();
        var createTime = OffsetDateTime.now();
        var accessTokenExpiresTime = createTime.plusSeconds(tokenConfig.getAccessTokenValiditySeconds());
        var accessToken = tokenStore.createToken(new OrzAuthTokenPayloadBo(
                uuid,
                userId,
                userType,
                clientType,
                accessTokenExpiresTime,
                createTime,
                OrzAuthTokenTypeBo.ACCESS,
                issuer,
                extras
        ));

        var refreshTokenExpiresTime = createTime.plusSeconds(tokenConfig.getRefreshTokenValiditySeconds());
        var refreshToken = tokenStore.createToken(new OrzAuthTokenPayloadBo(
                uuid,
                userId,
                userType,
                clientType,
                refreshTokenExpiresTime,
                createTime,
                OrzAuthTokenTypeBo.REFRESH,
                issuer,
                extras
        ));

        return new OrzAuthTokenInfoBo(
                userId,
                userType,
                accessToken,
                refreshToken,
                accessTokenExpiresTime,
                refreshTokenExpiresTime,
                issuer,
                extras
        );
    }

    public OrzAuthTokenInfoBo refreshToken(String token) throws OrzAuthTokenVerifyException {
        return refreshToken(token, null);
    }

    public OrzAuthTokenInfoBo refreshToken(String token, @Nullable String issuer) throws OrzAuthTokenVerifyException {
        var tokenIssuer = defaultIssuer(issuer);
        var tokenPayload = selectTokenStore(tokenIssuer).verifyToken(token, OrzAuthTokenTypeBo.REFRESH);
        checkTokenPayload(tokenPayload);
        return createToken(tokenPayload.getUserId(), tokenPayload.getUserType(), tokenPayload.getClientType(), tokenPayload.getExtras(), tokenIssuer);
    }

    protected OrzAuthTokenStore selectTokenStore(String issuer) {
        if (issuer.equals(defaultTokenIssuer)) {
            if (tokenStore != null) {
                return tokenStore;
            }
            synchronized (this) {
                if (tokenStore == null) {
                    var jwtConfig = props.getJwtConfig(scope);
                    var jsonMapper = OrzBaseUtils.getAppContext().getBean(JsonMapper.class);
                    tokenStore = new OrzAuthJwtTokenStore(jsonMapper, jwtConfig.getJksPath(), jwtConfig.getJksPassword(), jwtConfig.getJksAliasName(), jwtConfig.getJksAliasPassword());
                }
            }
            return tokenStore;
        } else {
            throw new OrzUnexpectedException("issuer not support: " + issuer);
        }
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
                OrzWebUtils.setRequestAttribute(USER_PAYLOAD_ATTRIBUTE_NAME, userPayload);
            }
            OrzWebUtils.setRequestAttribute(TOKEN_PAYLOAD_ATTRIBUTE_NAME, context.getTokenPayload());
        }
    }

    protected String obtainScope() {
        return OrzWebUtils.getScope(getClass());
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

        if (!Strings.CI.startsWith(authorization, "bearer ")) {
            return nullOrThrow.apply(new ResponseStatusException(401, "header authorization not bearer", null));
        }

        var accessToken = authorization.substring("bearer ".length());
        if (StringUtils.isEmpty(accessToken)) {
            return nullOrThrow.apply(new ResponseStatusException(401, "access token not provided", null));
        }

        var tokenIssuer = defaultIssuer(context.getRequest().getHeader("Orz-Token-Issuer"));
        try {
            var tokenPayload = selectTokenStore(tokenIssuer).verifyToken(accessToken, OrzAuthTokenTypeBo.ACCESS);
            checkTokenPayload(tokenPayload);
            return tokenPayload;
        } catch (OrzAuthTokenVerifyException e) {
            return nullOrThrow.apply(switch (e.getError()) {
                case TOKEN_INVALID, TOKEN_EXPIRED -> new ResponseStatusException(401, e.getError().name(), e);
                case INTERNAL_ERROR -> new OrzUnexpectedException(
                        "error", e.getError(), "tokenIssuer", tokenIssuer, e
                );
            });
        }
    }

    protected void checkTokenPayload(OrzAuthTokenPayloadBo payload) throws OrzAuthTokenVerifyException {
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
        var headers = OrzWebUtils.getRequestHeaders();
        var userIdMismatch = false;
        if (StringUtils.isNotBlank(headers.getUserId())) {
            userIdMismatch = !Objects.equals(headers.getUserId(), payload.getUserId());
        } else {
            userIdMismatch = !context.getConfig().isOptional();
        }
        if (userIdMismatch) {
            log.error(desc("request header mismatch", "field", "userId",
                    "headerUserId", headers.getUserId(),
                    "headerUserType", headers.getUserType(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenUserType", payload.getUserType(),
                    "tokenClientType", payload.getClientType()
            ));
            alarm("@ORZ_AUTH_CHECK_HEADER_FAILED", "userId mismatch", null, hashMap(
                    "headerUserId", headers.getUserId(),
                    "headerUserType", headers.getUserType(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenUserType", payload.getUserType(),
                    "tokenClientType", payload.getClientType()
            ));
        }
        var userTypeMismatch = false;
        if (StringUtils.isNotBlank(headers.getUserType())) {
            userTypeMismatch = !Objects.equals(headers.getUserType(), payload.getUserType());
        } else {
            userTypeMismatch = !context.getConfig().isOptional();
        }
        if (userTypeMismatch) {
            log.error(desc("request header mismatch", "field", "userType",
                    "headerUserId", headers.getUserId(),
                    "headerUserType", headers.getUserType(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenUserType", payload.getUserType(),
                    "tokenClientType", payload.getClientType()
            ));
            alarm("@ORZ_AUTH_CHECK_HEADER_FAILED", "userType mismatch", null, hashMap(
                    "headerUserId", headers.getUserId(),
                    "headerUserType", headers.getUserType(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenUserType", payload.getUserType(),
                    "tokenClientType", payload.getClientType()
            ));
        }
        boolean clientTypeMismatch = !Objects.equals(headers.getClientType(), payload.getClientType());
        if (clientTypeMismatch) {
            log.error(desc("request header mismatch", "field", "clientType",
                    "headerUserId", headers.getUserId(),
                    "headerUserType", headers.getUserType(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenUserType", payload.getUserType(),
                    "tokenClientType", payload.getClientType()
            ));
            alarm("@ORZ_AUTH_CHECK_HEADER_FAILED", "clientType mismatch", null, hashMap(
                    "headerUserId", headers.getUserId(),
                    "headerUserType", headers.getUserType(),
                    "headerClientType", headers.getClientType(),
                    "tokenUserId", payload.getUserId(),
                    "tokenUserType", payload.getUserType(),
                    "tokenClientType", payload.getClientType()
            ));
        }
        if (userIdMismatch || userTypeMismatch || clientTypeMismatch) {
            if (!context.getConfig().isOptional()) {
                throw new ResponseStatusException(403, "request header invalid", null);
            }
        }
    }

    @Nullable
    protected Object obtainUserPayload(OrzAuthContextBo context) {
        return null;
    }

    private String defaultIssuer(@Nullable String issuer) {
        return StringUtils.isNotBlank(issuer) ? issuer : defaultTokenIssuer;
    }
}
