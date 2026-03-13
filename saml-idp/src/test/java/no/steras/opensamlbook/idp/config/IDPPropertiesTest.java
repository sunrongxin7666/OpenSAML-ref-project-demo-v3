package no.steras.opensamlbook.idp.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IDPPropertiesTest {

    @Test
    void getterAndSetter_shouldReadWriteProperties() {
        IDPProperties props = new IDPProperties();
        props.setEntityId("https://idp.example.com");
        props.setSsoService("https://idp.example.com/sso");
        props.setArtifactResolutionService("https://idp.example.com/ars");
        props.setKeystorePath("classpath:idp-keystore.jks");
        props.setKeystorePassword("secret");
        props.setKeyAlias("idp-key");
        props.setKeyPassword("keypass");

        assertThat(props.getEntityId()).isEqualTo("https://idp.example.com");
        assertThat(props.getSsoService()).isEqualTo("https://idp.example.com/sso");
        assertThat(props.getArtifactResolutionService()).isEqualTo("https://idp.example.com/ars");
        assertThat(props.getKeystorePath()).isEqualTo("classpath:idp-keystore.jks");
        assertThat(props.getKeystorePassword()).isEqualTo("secret");
        assertThat(props.getKeyAlias()).isEqualTo("idp-key");
        assertThat(props.getKeyPassword()).isEqualTo("keypass");
    }

    @Test
    void spNestedProperties_shouldReadWrite() {
        IDPProperties props = new IDPProperties();
        IDPProperties.Sp sp = new IDPProperties.Sp();
        sp.setAssertionConsumerService("https://sp.example.com/consumer");
        sp.setEntityId("https://sp.example.com");
        props.setSp(sp);

        assertThat(props.getSp()).isNotNull();
        assertThat(props.getSp().getAssertionConsumerService()).isEqualTo("https://sp.example.com/consumer");
        assertThat(props.getSp().getEntityId()).isEqualTo("https://sp.example.com");
    }

    @Test
    void spDefault_shouldNotBeNull() {
        IDPProperties props = new IDPProperties();
        assertThat(props.getSp()).isNotNull();
    }
}
