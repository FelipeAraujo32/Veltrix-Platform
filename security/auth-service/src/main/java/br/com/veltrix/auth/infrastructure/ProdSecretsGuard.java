package br.com.veltrix.auth.infrastructure;

import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Fail-fast do perfil de produção (invariante fail-closed): se um segredo ou uma
 * configuração obrigatória estiver ausente, em branco ou com placeholder não
 * resolvível, o serviço NÃO sobe. Roda como {@link BeanFactoryPostProcessor} para
 * falhar antes de qualquer bean de aplicação (DataSource, Flyway, JwtKeyProvider)
 * com uma mensagem que aponta exatamente o que falta.
 *
 * <p>Fontes esperadas em produção: Docker secret via configtree
 * ({@code /run/secrets/<nome-da-property>}) ou a env var correspondente — nunca um
 * default embutido. No perfil dev local este guard não é registrado.</p>
 */
@Component
@Profile("prod")
public class ProdSecretsGuard implements BeanFactoryPostProcessor, EnvironmentAware {

    // EnvironmentAware (e não injeção por construtor): BeanFactoryPostProcessors são
    // instanciados antes do AutowiredAnnotationBeanPostProcessor estar ativo.
    private Environment environment;

    public ProdSecretsGuard() {
    }

    ProdSecretsGuard(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        List<String> missing = new ArrayList<>();
        requireNonBlank(missing, "spring.datasource.url");
        requireNonBlank(missing, "spring.datasource.username");
        requireNonBlank(missing, "spring.datasource.password");
        requireNonBlank(missing, "jwt.private-key-path");
        requireNonBlank(missing, "jwt.key-id");
        requireNonBlank(missing, "security.allowed-origins");
        if (!missing.isEmpty())
            throw new IllegalStateException("Production profile is fail-closed: missing or blank required configuration "
                    + missing + ". Provide each value as a Docker secret file /run/secrets/<property-name> (configtree) "
                    + "or as the corresponding environment variable. Refusing to start.");
    }

    private void requireNonBlank(List<String> missing, String property) {
        try {
            String value = environment.getProperty(property);
            if (value == null || value.isBlank()) missing.add(property);
        } catch (IllegalArgumentException unresolvablePlaceholder) {
            missing.add(property);
        }
    }
}
