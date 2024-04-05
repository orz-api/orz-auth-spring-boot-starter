package orz.springboot.auth.model;

import jakarta.annotation.Nullable;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class OrzAuthTokenPayloadBo {
    private final String uuid;
    private final String userId;
    private final String clientType;
    @Nullable
    private final OffsetDateTime createTime;
    private final OffsetDateTime expiresTime;
}
