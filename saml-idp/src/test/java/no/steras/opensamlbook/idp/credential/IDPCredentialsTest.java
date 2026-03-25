package no.steras.opensamlbook.idp.credential;

import no.steras.opensamlbook.config.OpenSAMLConfig;
import no.steras.opensamlbook.idp.config.IDPProperties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IDPCredentialsTest {

    @BeforeAll
    static void initOpenSAML() {
        new OpenSAMLConfig().init();
    }

    private IDPProperties buildProperties(String keystorePath, String password, String alias, String keyPassword) {
        IDPProperties props = new IDPProperties();
        props.setKeystorePath(keystorePath);
        props.setKeystorePassword(password);
        props.setKeyAlias(alias);
        props.setKeyPassword(keyPassword);
        return props;
    }

    @Test
    void init_shouldLoadKeystoreCredentialSuccessfully() {
        IDPProperties props = buildProperties("classpath:IDPKeystore.jks", "password", "IDPKey", "password");
        ResourceLoader resourceLoader = new DefaultResourceLoader();

        IDPCredentials credentials = new IDPCredentials(props, resourceLoader);
        credentials.init();

        assertThat(credentials.getCredential()).isNotNull();
        assertThat(credentials.getCredential().getPrivateKey()).isNotNull();
        assertThat(credentials.getCredential().getPublicKey()).isNotNull();
    }

    @Test
    void init_shouldThrowExceptionForInvalidKeystorePath() {
        IDPProperties props = buildProperties("classpath:nonexistent.jks", "password", "alias", "password");
        ResourceLoader resourceLoader = new DefaultResourceLoader();

        IDPCredentials credentials = new IDPCredentials(props, resourceLoader);

        assertThatThrownBy(credentials::init)
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to load IDP keystore");
    }

    @Test
    void init_shouldThrowExceptionForWrongPassword() {
        IDPProperties props = buildProperties("classpath:IDPKeystore.jks", "wrongpassword", "IDPKey", "password");
        ResourceLoader resourceLoader = new DefaultResourceLoader();

        IDPCredentials credentials = new IDPCredentials(props, resourceLoader);

        assertThatThrownBy(credentials::init)
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void getCredential_shouldReturnNullBeforeInit() {
        IDPProperties props = buildProperties("classpath:IDPKeystore.jks", "password", "IDPKey", "password");
        ResourceLoader resourceLoader = new DefaultResourceLoader();

        IDPCredentials credentials = new IDPCredentials(props, resourceLoader);

        assertThat(credentials.getCredential()).isNull();
    }
}
