package orz.springboot.auth.model;

import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OrzAuthTokenPayloadPo {
    private String uuid;
    private String userId;
    private String userRole;
    private String clientType;
    private OffsetDateTime expiresTime;
    private OffsetDateTime createTime;
    private OrzAuthTokenTypePo tokenType;
    @Nullable
    private Map<String, Object> extras;
}
