package orz.springboot.auth.model;

import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OrzAuthTokenPayloadPo {
    private String uuid;
    private String userId;
    private String clientType;
    private OffsetDateTime expiresTime;
    @Nullable
    private OffsetDateTime createTime;
    @Nullable
    private OrzAuthTokenTypePo tokenType;
}
