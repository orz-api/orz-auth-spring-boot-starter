package orz.springboot.auth.annotation;

import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface OrzAuth {
    boolean optional();

    boolean checkRequestHeader() default true;

    String[] allowClientTypes() default {};
}
