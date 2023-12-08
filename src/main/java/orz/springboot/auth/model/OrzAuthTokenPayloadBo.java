package orz.springboot.auth.model;

import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class OrzAuthTokenPayloadBo {
    private final String uuid;
    private final String userId;
    private final String clientType;
    private final OffsetDateTime expiresTime;
}
