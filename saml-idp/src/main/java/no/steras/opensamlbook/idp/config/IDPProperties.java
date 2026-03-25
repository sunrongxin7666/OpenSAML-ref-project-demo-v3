package no.steras.opensamlbook.idp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "saml.idp")
public class IDPProperties {
    private String entityId;
    private String ssoService;
    private String artifactResolutionService;
    private String keystorePath;
    private String keystorePassword;
    private String keyAlias;
    private String keyPassword;

    private Sp sp = new Sp();

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

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

    public Sp getSp() {
        return sp;
    }

    public void setSp(Sp sp) {
        this.sp = sp;
    }

    public static class Sp {
        private String assertionConsumerService;
        private String entityId;

        public String getAssertionConsumerService() {
            return assertionConsumerService;
        }

        public void setAssertionConsumerService(String assertionConsumerService) {
            this.assertionConsumerService = assertionConsumerService;
        }

        public String getEntityId() {
            return entityId;
        }

        public void setEntityId(String entityId) {
            this.entityId = entityId;
        }
    }
}
