package orz.springboot.auth;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import orz.springboot.auth.model.OrzAuthTokenPayloadPo;
import orz.springboot.auth.model.OrzAuthTokenInfoTo;
import orz.springboot.auth.model.OrzAuthTokenTypePo;

public class OrzAuthRuntimeHintsRegistrar implements RuntimeHintsRegistrar {
    @Override
    public void registerHints(@NonNull RuntimeHints hints, @Nullable ClassLoader classLoader) {
        hints.reflection().registerTypes(
                TypeReference.listOf(OrzAuthTokenInfoTo.class, OrzAuthTokenPayloadPo.class, OrzAuthTokenTypePo.class),
                builder -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS)
        );
        hints.resources().registerPattern("orz/auth/*");
    }
}
