package no.steras.opensamlbook.sp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "saml.sp")
public class SPProperties {
    private String entityId;
    private String assertionConsumerService;
    private String keystorePath;
    private String keystorePassword;
    private String keyAlias;
    private String keyPassword;
    private String idpCertificatePath;

    private Idp idp = new Idp();

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public String getAssertionConsumerService() {
        return assertionConsumerService;
    }

    public void setAssertionConsumerService(String assertionConsumerService) {
        this.assertionConsumerService = assertionConsumerService;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public void setKeystorePath(String keystorePath) {
        this.keystorePath = keystorePath;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getIdpCertificatePath() {
        return idpCertificatePath;
    }

    public void setIdpCertificatePath(String idpCertificatePath) {
        this.idpCertificatePath = idpCertificatePath;
    }

    public Idp getIdp() {
        return idp;
    }

    public void setIdp(Idp idp) {
        this.idp = idp;
    }

    public static class Idp {
        private String ssoService;
        private String artifactResolutionService;

        public String getSsoService() {
            return ssoService;
        }

        public void setSsoService(String ssoService) {
            this.ssoService = ssoService;
        }

        public String getArtifactResolutionService() {
            return artifactResolutionService;
        }

        public void setArtifactResolutionService(String artifactResolutionService) {
            this.artifactResolutionService = artifactResolutionService;
        }
    }
}
