package orz.springboot.auth.model;

import lombok.Data;

import java.util.Set;

@Data
public class OrzAuthConfigBo {
    private final boolean optional;
    private final boolean checkRequestHeader;
    private final Set<String> allowClientTypeSet;
}
