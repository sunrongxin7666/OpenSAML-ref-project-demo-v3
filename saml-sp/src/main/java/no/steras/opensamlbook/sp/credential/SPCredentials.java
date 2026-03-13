package no.steras.opensamlbook.sp.credential;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import no.steras.opensamlbook.sp.config.SPProperties;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;

@Component
public class SPCredentials {
    private static final Logger logger = LoggerFactory.getLogger(SPCredentials.class);

    private final SPProperties spProperties;
    private final ResourceLoader resourceLoader;
    private Credential credential;
    private Credential idpVerificationCredential;

    public SPCredentials(SPProperties spProperties, ResourceLoader resourceLoader) {
        this.spProperties = spProperties;
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() {
        loadSpCredential();
        loadIdpVerificationCredential();
    }

    private void loadSpCredential() {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            Resource resource = resourceLoader.getResource(spProperties.getKeystorePath());
            InputStream inputStream = resource.getInputStream();
            keystore.load(inputStream, spProperties.getKeystorePassword().toCharArray());
            inputStream.close();

            Map<String, String> passwordMap = new HashMap<String, String>();
            passwordMap.put(spProperties.getKeyAlias(), spProperties.getKeyPassword());
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

            Criterion criterion = new EntityIdCriterion(spProperties.getKeyAlias());
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(criterion);

            credential = resolver.resolveSingle(criteriaSet);
            logger.info("SP credentials loaded from keystore");
        } catch (ResolverException e) {
            throw new RuntimeException("Failed to read SP credentials", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load SP keystore", e);
        }
    }

    private void loadIdpVerificationCredential() {
        try {
            Resource resource = resourceLoader.getResource(spProperties.getIdpCertificatePath());
            InputStream inputStream = resource.getInputStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(inputStream);
            inputStream.close();

            idpVerificationCredential = CredentialSupport.getSimpleCredential(cert.getPublicKey(), null);
            logger.info("IDP verification credential loaded from certificate");
        } catch (Exception e) {
            throw new RuntimeException("Failed to load IDP certificate", e);
        }
    }

    public Credential getCredential() {
        return credential;
    }

    public Credential getIdpVerificationCredential() {
        return idpVerificationCredential;
    }
}
