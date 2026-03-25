package no.steras.opensamlbook.sp.credential;

import no.steras.opensamlbook.config.OpenSAMLConfig;
import no.steras.opensamlbook.sp.config.SPProperties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SPCredentialsTest {

    @BeforeAll
    static void initOpenSAML() {
        new OpenSAMLConfig().init();
    }

    private SPProperties buildProperties(String keystorePath, String password, String alias,
                                         String keyPassword, String idpCertPath) {
        SPProperties props = new SPProperties();
        props.setKeystorePath(keystorePath);
        props.setKeystorePassword(password);
        props.setKeyAlias(alias);
        props.setKeyPassword(keyPassword);
        props.setIdpCertificatePath(idpCertPath);
        return props;
    }

    @Test
    void init_shouldLoadSpCredentialAndIdpVerificationCredential() {
        SPProperties props = buildProperties("classpath:SPKeystore.jks", "password", "SPKey",
                "password", "classpath:idp-certificate.crt");
        ResourceLoader resourceLoader = new DefaultResourceLoader();

        SPCredentials credentials = new SPCredentials(props, resourceLoader);
        credentials.init();

        assertThat(credentials.getCredential()).isNotNull();
        assertThat(credentials.getCredential().getPrivateKey()).isNotNull();
        assertThat(credentials.getCredential().getPublicKey()).isNotNull();
        assertThat(credentials.getIdpVerificationCredential()).isNotNull();
        assertThat(credentials.getIdpVerificationCredential().getPublicKey()).isNotNull();
    }

    @Test
    void init_shouldThrowExceptionForInvalidKeystorePath() {
        SPProperties props = buildProperties("classpath:nonexistent.jks", "password", "alias",
                "password", "classpath:idp-certificate.crt");
        ResourceLoader resourceLoader = new DefaultResourceLoader();

        SPCredentials credentials = new SPCredentials(props, resourceLoader);

        assertThatThrownBy(credentials::init)
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to load SP keystore");
    }

    @Test
    void init_shouldThrowExceptionForInvalidIdpCertPath() {
        SPProperties props = buildProperties("classpath:SPKeystore.jks", "password", "SPKey",
                "password", "classpath:nonexistent.crt");
        ResourceLoader resourceLoader = new DefaultResourceLoader();

        SPCredentials credentials = new SPCredentials(props, resourceLoader);

        assertThatThrownBy(credentials::init)
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to load IDP certificate");
    }

    @Test
    void getCredential_shouldReturnNullBeforeInit() {
        SPProperties props = buildProperties("classpath:SPKeystore.jks", "password", "SPKey",
                "password", "classpath:idp-certificate.crt");
        ResourceLoader resourceLoader = new DefaultResourceLoader();

        SPCredentials credentials = new SPCredentials(props, resourceLoader);

        assertThat(credentials.getCredential()).isNull();
        assertThat(credentials.getIdpVerificationCredential()).isNull();
    }
}
