package no.steras.opensamlbook.sp.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SPPropertiesTest {

    @Test
    void getterAndSetter_shouldReadWriteProperties() {
        SPProperties props = new SPProperties();
        props.setEntityId("https://sp.example.com");
        props.setAssertionConsumerService("https://sp.example.com/consumer");
        props.setKeystorePath("classpath:sp-keystore.jks");
        props.setKeystorePassword("secret");
        props.setKeyAlias("sp-key");
        props.setKeyPassword("keypass");
        props.setIdpCertificatePath("classpath:idp-cert.crt");

        assertThat(props.getEntityId()).isEqualTo("https://sp.example.com");
        assertThat(props.getAssertionConsumerService()).isEqualTo("https://sp.example.com/consumer");
        assertThat(props.getKeystorePath()).isEqualTo("classpath:sp-keystore.jks");
        assertThat(props.getKeystorePassword()).isEqualTo("secret");
        assertThat(props.getKeyAlias()).isEqualTo("sp-key");
        assertThat(props.getKeyPassword()).isEqualTo("keypass");
        assertThat(props.getIdpCertificatePath()).isEqualTo("classpath:idp-cert.crt");
    }

    @Test
    void idpNestedProperties_shouldReadWrite() {
        SPProperties props = new SPProperties();
        SPProperties.Idp idp = new SPProperties.Idp();
        idp.setSsoService("https://idp.example.com/sso");
        idp.setArtifactResolutionService("https://idp.example.com/ars");
        props.setIdp(idp);

        assertThat(props.getIdp()).isNotNull();
        assertThat(props.getIdp().getSsoService()).isEqualTo("https://idp.example.com/sso");
        assertThat(props.getIdp().getArtifactResolutionService()).isEqualTo("https://idp.example.com/ars");
    }

    @Test
    void idpDefault_shouldNotBeNull() {
        SPProperties props = new SPProperties();
        assertThat(props.getIdp()).isNotNull();
    }
}
