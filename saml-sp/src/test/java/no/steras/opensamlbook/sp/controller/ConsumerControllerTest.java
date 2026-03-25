package no.steras.opensamlbook.sp.controller;

import no.steras.opensamlbook.OpenSAMLUtils;
import no.steras.opensamlbook.config.OpenSAMLConfig;
import no.steras.opensamlbook.sp.filter.SamlAccessFilter;
import no.steras.opensamlbook.sp.service.SamlSpService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ConsumerControllerTest {

    private ConsumerController consumerController;
    private SamlSpService samlSpService;

    @BeforeAll
    static void initOpenSAML() {
        new OpenSAMLConfig().init();
    }

    @BeforeEach
    void setUp() {
        samlSpService = mock(SamlSpService.class);
        consumerController = new ConsumerController(samlSpService);
    }

    @Test
    void consumeAssertion_shouldSetAuthenticatedSessionAttribute() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("SAMLart", "testArtifact");
        MockHttpServletResponse response = new MockHttpServletResponse();

        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact("testArtifact");
        when(samlSpService.buildArtifactFromRequest(any())).thenReturn(artifact);

        ArtifactResolve resolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);
        when(samlSpService.buildArtifactResolve(any())).thenReturn(resolve);

        ArtifactResponse artifactResponse = OpenSAMLUtils.buildSAMLObject(ArtifactResponse.class);
        when(samlSpService.sendAndReceiveArtifactResolve(any())).thenReturn(artifactResponse);

        EncryptedAssertion encryptedAssertion = OpenSAMLUtils.buildSAMLObject(EncryptedAssertion.class);
        when(samlSpService.getEncryptedAssertion(any())).thenReturn(encryptedAssertion);

        Assertion assertion = buildMinimalAssertion();
        when(samlSpService.decryptAssertion(any())).thenReturn(assertion);

        consumerController.consumeAssertion(request, response);

        assertThat(request.getSession().getAttribute(SamlAccessFilter.AUTHENTICATED_SESSION_ATTRIBUTE))
                .isEqualTo(true);
    }

    @Test
    void consumeAssertion_shouldRedirectToGotoUrlWhenSet() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("SAMLart", "testArtifact");
        request.getSession().setAttribute(SamlAccessFilter.GOTO_URL_SESSION_ATTRIBUTE, "/app/dashboard");
        MockHttpServletResponse response = new MockHttpServletResponse();

        setupMocksForConsumeAssertion();

        consumerController.consumeAssertion(request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo("/app/dashboard");
    }

    @Test
    void consumeAssertion_shouldRedirectToDefaultWhenNoGotoUrl() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("SAMLart", "testArtifact");
        MockHttpServletResponse response = new MockHttpServletResponse();

        setupMocksForConsumeAssertion();

        consumerController.consumeAssertion(request, response);

        assertThat(response.getRedirectedUrl()).isEqualTo("/app/appservlet");
    }

    @Test
    void consumeAssertion_shouldCallAllServiceMethods() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("SAMLart", "testArtifact");
        MockHttpServletResponse response = new MockHttpServletResponse();

        setupMocksForConsumeAssertion();

        consumerController.consumeAssertion(request, response);

        verify(samlSpService).buildArtifactFromRequest(request);
        verify(samlSpService).buildArtifactResolve(any());
        verify(samlSpService).sendAndReceiveArtifactResolve(any());
        verify(samlSpService).validateDestinationAndLifetime(any(), eq(request));
        verify(samlSpService).getEncryptedAssertion(any());
        verify(samlSpService).decryptAssertion(any());
        verify(samlSpService).verifyAssertionSignature(any());
        verify(samlSpService).logAssertionAttributes(any());
        verify(samlSpService).logAuthenticationInstant(any());
        verify(samlSpService).logAuthenticationMethod(any());
    }

    private void setupMocksForConsumeAssertion() {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact("testArtifact");
        when(samlSpService.buildArtifactFromRequest(any())).thenReturn(artifact);

        ArtifactResolve resolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);
        when(samlSpService.buildArtifactResolve(any())).thenReturn(resolve);

        ArtifactResponse artifactResponse = OpenSAMLUtils.buildSAMLObject(ArtifactResponse.class);
        when(samlSpService.sendAndReceiveArtifactResolve(any())).thenReturn(artifactResponse);

        EncryptedAssertion encryptedAssertion = OpenSAMLUtils.buildSAMLObject(EncryptedAssertion.class);
        when(samlSpService.getEncryptedAssertion(any())).thenReturn(encryptedAssertion);

        Assertion assertion = buildMinimalAssertion();
        when(samlSpService.decryptAssertion(any())).thenReturn(assertion);
    }

    private Assertion buildMinimalAssertion() {
        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);
        assertion.setID("test-id");
        assertion.setIssueInstant(new org.joda.time.DateTime());

        // Add attribute statement
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

        // Add authn statement
        AuthnStatement authnStmt = OpenSAMLUtils.buildSAMLObject(AuthnStatement.class);
        authnStmt.setAuthnInstant(new org.joda.time.DateTime());
        AuthnContext authnContext = OpenSAMLUtils.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef classRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        classRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(classRef);
        authnStmt.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStmt);

        return assertion;
    }
}
