package no.steras.opensamlbook.idp.service;

import no.steras.opensamlbook.OpenSAMLUtils;
import no.steras.opensamlbook.config.OpenSAMLConfig;
import no.steras.opensamlbook.idp.config.IDPProperties;
import no.steras.opensamlbook.idp.credential.IDPCredentials;
import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.credential.Credential;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;

import static org.assertj.core.api.Assertions.assertThat;

class SamlIdpServiceTest {

    private SamlIdpService samlIdpService;
    private IDPCredentials idpCredentials;
    private IDPProperties idpProperties;

    @BeforeAll
    static void initOpenSAML() {
        new OpenSAMLConfig().init();
    }

    @BeforeEach
    void setUp() {
        idpProperties = new IDPProperties();
        idpProperties.setEntityId("https://idp.example.com");
        IDPProperties.Sp sp = new IDPProperties.Sp();
        sp.setAssertionConsumerService("https://sp.example.com/consumer");
        sp.setEntityId("https://sp.example.com");
        idpProperties.setSp(sp);
        idpProperties.setKeystorePath("classpath:IDPKeystore.jks");
        idpProperties.setKeystorePassword("password");
        idpProperties.setKeyAlias("IDPKey");
        idpProperties.setKeyPassword("password");

        ResourceLoader resourceLoader = new DefaultResourceLoader();
        idpCredentials = new IDPCredentials(idpProperties, resourceLoader);
        idpCredentials.init();

        samlIdpService = new SamlIdpService(idpProperties, idpCredentials);
    }

    @Test
    void buildArtifactResponse_shouldBuildCorrectResponse() {
        Credential spCredential = idpCredentials.getCredential();

        ArtifactResponse response = samlIdpService.buildArtifactResponse(spCredential);

        assertThat(response).isNotNull();
        assertThat(response.getIssuer().getValue()).isEqualTo("https://idp.example.com");
        assertThat(response.getDestination()).isEqualTo("https://sp.example.com/consumer");
        assertThat(response.getID()).isNotNull();
        assertThat(response.getStatus().getStatusCode().getValue())
                .isEqualTo("urn:oasis:names:tc:SAML:2.0:status:Success");
    }

    @Test
    void buildArtifactResponse_shouldContainInnerResponse() {
        Credential spCredential = idpCredentials.getCredential();

        ArtifactResponse artifactResponse = samlIdpService.buildArtifactResponse(spCredential);
        Response innerResponse = (Response) artifactResponse.getMessage();

        assertThat(innerResponse).isNotNull();
        assertThat(innerResponse.getIssuer().getValue()).isEqualTo("https://idp.example.com");
        assertThat(innerResponse.getDestination()).isEqualTo("https://sp.example.com/consumer");
        assertThat(innerResponse.getEncryptedAssertions()).hasSize(1);
    }

    @Test
    void signAssertion_shouldSignSuccessfully() {
        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);
        assertion.setID("test-id");
        assertion.setIssueInstant(new DateTime());

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue("https://idp.example.com");
        assertion.setIssuer(issuer);

        samlIdpService.signAssertion(assertion);

        assertThat(assertion.getSignature()).isNotNull();
        assertThat(assertion.isSigned()).isTrue();
    }

    @Test
    void encryptAssertion_shouldEncryptSuccessfully() {
        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);
        assertion.setID("test-id");
        assertion.setIssueInstant(new DateTime());

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue("https://idp.example.com");
        assertion.setIssuer(issuer);

        Credential spCredential = idpCredentials.getCredential();
        EncryptedAssertion encrypted = samlIdpService.encryptAssertion(assertion, spCredential);

        assertThat(encrypted).isNotNull();
        assertThat(encrypted.getEncryptedData()).isNotNull();
    }

    @Test
    void buildArtifactResponse_shouldSetIssueInstant() {
        Credential spCredential = idpCredentials.getCredential();
        DateTime before = new DateTime();

        ArtifactResponse response = samlIdpService.buildArtifactResponse(spCredential);

        assertThat(response.getIssueInstant()).isNotNull();
        assertThat(response.getIssueInstant().isAfter(before.minusSeconds(1))).isTrue();
    }
}
