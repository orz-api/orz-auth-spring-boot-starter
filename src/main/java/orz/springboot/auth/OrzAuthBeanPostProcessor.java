package orz.springboot.auth;

import jakarta.annotation.Nonnull;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

@Component
public class OrzAuthBeanPostProcessor implements BeanPostProcessor {
    private final OrzAuthManager authManager;

    @Lazy
    public OrzAuthBeanPostProcessor(OrzAuthManager authManager) {
        this.authManager = authManager;
    }

    @Override
    public Object postProcessAfterInitialization(@Nonnull Object bean, @Nonnull String beanName) throws BeansException {
        if (bean instanceof OrzAuthService service) {
            authManager.registerService(service);
        }
        return BeanPostProcessor.super.postProcessAfterInitialization(bean, beanName);
    }
}
