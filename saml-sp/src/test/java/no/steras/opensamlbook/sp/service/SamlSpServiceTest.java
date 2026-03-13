package no.steras.opensamlbook.sp.service;

import no.steras.opensamlbook.OpenSAMLUtils;
import no.steras.opensamlbook.config.OpenSAMLConfig;
import no.steras.opensamlbook.sp.config.SPProperties;
import no.steras.opensamlbook.sp.credential.SPCredentials;
import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.*;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SamlSpServiceTest {

    private SamlSpService samlSpService;
    private SPProperties spProperties;
    private SPCredentials spCredentials;

    @BeforeAll
    static void initOpenSAML() {
        new OpenSAMLConfig().init();
    }

    @BeforeEach
    void setUp() {
        spProperties = new SPProperties();
        spProperties.setEntityId("https://sp.example.com");
        spProperties.setAssertionConsumerService("https://sp.example.com/consumer");
        SPProperties.Idp idp = new SPProperties.Idp();
        idp.setSsoService("https://idp.example.com/sso");
        idp.setArtifactResolutionService("https://idp.example.com/ars");
        spProperties.setIdp(idp);

        spCredentials = mock(SPCredentials.class);
        samlSpService = new SamlSpService(spProperties, spCredentials);
    }

    @Test
    void buildArtifactFromRequest_shouldExtractSAMLartParam() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("SAMLart", "testArtifactValue");

        Artifact artifact = samlSpService.buildArtifactFromRequest(request);

        assertThat(artifact).isNotNull();
        assertThat(artifact.getArtifact()).isEqualTo("testArtifactValue");
    }

    @Test
    void buildArtifactResolve_shouldBuildCorrectRequest() {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact("testArtifact");

        ArtifactResolve resolve = samlSpService.buildArtifactResolve(artifact);

        assertThat(resolve).isNotNull();
        assertThat(resolve.getIssuer().getValue()).isEqualTo("https://sp.example.com");
        assertThat(resolve.getDestination()).isEqualTo("https://idp.example.com/ars");
        assertThat(resolve.getID()).isNotNull();
        assertThat(resolve.getArtifact().getArtifact()).isEqualTo("testArtifact");
    }

    @Test
    void buildArtifactResolve_shouldSetIssueInstant() {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact("test");
        DateTime before = new DateTime();

        ArtifactResolve resolve = samlSpService.buildArtifactResolve(artifact);

        assertThat(resolve.getIssueInstant()).isNotNull();
        assertThat(resolve.getIssueInstant().isAfter(before.minusSeconds(1))).isTrue();
    }

    @Test
    void getEncryptedAssertion_shouldExtractFromArtifactResponse() {
        ArtifactResponse artifactResponse = OpenSAMLUtils.buildSAMLObject(ArtifactResponse.class);
        Response response = OpenSAMLUtils.buildSAMLObject(Response.class);
        EncryptedAssertion encryptedAssertion = OpenSAMLUtils.buildSAMLObject(EncryptedAssertion.class);
        response.getEncryptedAssertions().add(encryptedAssertion);
        artifactResponse.setMessage(response);

        EncryptedAssertion result = samlSpService.getEncryptedAssertion(artifactResponse);

        assertThat(result).isNotNull();
        assertThat(result).isSameAs(encryptedAssertion);
    }

    @Test
    void verifyAssertionSignature_shouldThrowWhenNotSigned() {
        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);
        assertion.setID("test-id");
        assertion.setIssueInstant(new DateTime());

        assertThatThrownBy(() -> samlSpService.verifyAssertionSignature(assertion))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("not signed");
    }

    @Test
    void logAssertionAttributes_shouldNotThrowForValidAssertion() {
        Assertion assertion = buildAssertionWithAttributes();

        // should not throw
        samlSpService.logAssertionAttributes(assertion);
    }

    @Test
    void logAuthenticationInstant_shouldNotThrowForValidAssertion() {
        Assertion assertion = buildAssertionWithAuthnStatement();

        // should not throw
        samlSpService.logAuthenticationInstant(assertion);
    }

    @Test
    void logAuthenticationMethod_shouldNotThrowForValidAssertion() {
        Assertion assertion = buildAssertionWithAuthnStatement();

        // should not throw
        samlSpService.logAuthenticationMethod(assertion);
    }

    private Assertion buildAssertionWithAttributes() {
        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);
        assertion.setID("test-id");
        assertion.setIssueInstant(new DateTime());

        AttributeStatement attrStmt = OpenSAMLUtils.buildSAMLObject(AttributeStatement.class);
        Attribute attr = OpenSAMLUtils.buildSAMLObject(Attribute.class);
        attr.setName("username");

        org.opensaml.core.xml.schema.XSString value = (org.opensaml.core.xml.schema.XSString)
                org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .getBuilder(org.opensaml.core.xml.schema.XSString.TYPE_NAME)
                        .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, org.opensaml.core.xml.schema.XSString.TYPE_NAME);
        value.setValue("testuser");
        attr.getAttributeValues().add(value);
        attrStmt.getAttributes().add(attr);
        assertion.getAttributeStatements().add(attrStmt);

        return assertion;
    }

    private Assertion buildAssertionWithAuthnStatement() {
        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);
        assertion.setID("test-id");
        assertion.setIssueInstant(new DateTime());

        AuthnStatement authnStmt = OpenSAMLUtils.buildSAMLObject(AuthnStatement.class);
        authnStmt.setAuthnInstant(new DateTime());

        AuthnContext authnContext = OpenSAMLUtils.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef classRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        classRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(classRef);
        authnStmt.setAuthnContext(authnContext);

        assertion.getAuthnStatements().add(authnStmt);
        return assertion;
    }
}
