package no.steras.opensamlbook.config;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.security.Provider;
import java.security.Security;

@Configuration
public class OpenSAMLConfig {
    private static final Logger logger = LoggerFactory.getLogger(OpenSAMLConfig.class);

    @PostConstruct
    public void init() {
        JavaCryptoValidationInitializer javaCryptoValidationInitializer =
                new JavaCryptoValidationInitializer();
        try {
            javaCryptoValidationInitializer.init();
        } catch (InitializationException e) {
            throw new RuntimeException("JCE validation failed", e);
        }

        for (Provider jceProvider : Security.getProviders()) {
            logger.info(jceProvider.getInfo());
        }

        try {
            logger.info("Initializing OpenSAML");
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("OpenSAML initialization failed", e);
        }
    }
}
