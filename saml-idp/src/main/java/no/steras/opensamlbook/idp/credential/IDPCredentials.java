package no.steras.opensamlbook.idp.credential;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import no.steras.opensamlbook.idp.config.IDPProperties;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

@Component
public class IDPCredentials {
    private static final Logger logger = LoggerFactory.getLogger(IDPCredentials.class);

    private final IDPProperties idpProperties;
    private final ResourceLoader resourceLoader;
    private Credential credential;

    public IDPCredentials(IDPProperties idpProperties, ResourceLoader resourceLoader) {
        this.idpProperties = idpProperties;
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            Resource resource = resourceLoader.getResource(idpProperties.getKeystorePath());
            InputStream inputStream = resource.getInputStream();
            keystore.load(inputStream, idpProperties.getKeystorePassword().toCharArray());
            inputStream.close();

            Map<String, String> passwordMap = new HashMap<String, String>();
            passwordMap.put(idpProperties.getKeyAlias(), idpProperties.getKeyPassword());
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

            Criterion criterion = new EntityIdCriterion(idpProperties.getKeyAlias());
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(criterion);

            credential = resolver.resolveSingle(criteriaSet);
            logger.info("IDP credentials loaded from keystore");
        } catch (ResolverException e) {
            throw new RuntimeException("Failed to read IDP credentials", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load IDP keystore", e);
        }
    }

    public Credential getCredential() {
        return credential;
    }
}
