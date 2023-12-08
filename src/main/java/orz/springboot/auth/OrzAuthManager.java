package orz.springboot.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.FatalBeanException;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import orz.springboot.web.OrzWebUtils;

import java.util.HashMap;
import java.util.Map;

import static orz.springboot.base.OrzBaseUtils.assertion;
import static orz.springboot.base.description.OrzDescriptionUtils.desc;

@Component
public class OrzAuthManager {
    private final Map<String, OrzAuthService> serviceMap = new HashMap<>();

    public synchronized void registerService(OrzAuthService service) {
        assertion(service != null, "service != null");
        var exists = serviceMap.get(service.getScope());
        if (exists == service) {
            return;
        }
        if (exists != null) {
            throw new FatalBeanException(desc("auth service already exists", "scope", service.getScope(), "service", service.getClass().getName(), "exists", exists.getClass().getName()));
        }
        serviceMap.put(service.getScope(), service);
    }

    public boolean authorize(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (handler instanceof HandlerMethod handlerMethod) {
            var scope = OrzWebUtils.getScope(handlerMethod.getBeanType());
            if (scope != null) {
                var service = serviceMap.get(scope);
                if (service != null) {
                    service.authorize(request, response, handler);
                }
            }
        }
        return true;
    }
}
