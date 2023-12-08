package orz.springboot.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Component
public class OrzAuthWebMvcConfigurer implements WebMvcConfigurer {
    private final OrzAuthManager authManager;

    public OrzAuthWebMvcConfigurer(OrzAuthManager authManager) {
        this.authManager = authManager;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new Interceptor()).order(Ordered.HIGHEST_PRECEDENCE);
    }

    private class Interceptor implements HandlerInterceptor {
        @Override
        public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Object handler) throws Exception {
            return authManager.authorize(request, response, handler);
        }
    }
}
