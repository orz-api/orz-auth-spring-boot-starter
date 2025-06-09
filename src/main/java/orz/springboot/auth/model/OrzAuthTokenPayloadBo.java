package orz.springboot.auth.model;

import jakarta.annotation.Nullable;
import lombok.Data;

import java.time.OffsetDateTime;
import java.util.Map;

@Data
public class OrzAuthTokenPayloadBo {
    private final String uuid;
    private final String userId;
    private final String clientType;
    private final OffsetDateTime expiresTime;
    @Nullable
    private final OffsetDateTime createTime;
    @Nullable
    private final OrzAuthTokenTypeBo tokenType;
    @Nullable
    private final Map<String, Object> extras;
}
